import asyncio
import json
import threading
import errno
import pytest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import cloudmail_downloader as m

DATA = b'abcdefgh' * 100000

class Handler(BaseHTTPRequestHandler):
    ranges = []
    def log_message(self, *args): pass
    def do_GET(self):
        offset = int(self.headers.get('Range', 'bytes=0-').split('=')[1].split('-')[0])
        self.ranges.append(offset)
        self.send_response(206 if offset else 200)
        self.send_header('Content-Length', str(len(DATA)-offset))
        self.send_header('ETag', '"v1"')
        if offset: self.send_header('Content-Range',f'bytes {offset}-{len(DATA)-1}/{len(DATA)}')
        self.end_headers(); self.wfile.write(DATA[offset:])

def test_resume_and_no_overwrite():
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    try:
        with TemporaryDirectory() as directory, patch.object(m,'BASE',f'http://127.0.0.1:{server.server_port}/'):
            dav=m.DAV('user','test'); e=m.Entry('/file','file',False,len(DATA),etag='"v1"'); dest=Path(directory)/'file'
            cancelled=threading.Event()
            def update(*args): cancelled.set()
            assert dav.get(e,dest,update,cancelled.is_set) is False
            assert not dest.exists()
            # Seed a partial representing an earlier interrupted process.
            dest.with_name('file.part').write_bytes(DATA[:123456])
            assert dav.get(e,dest,lambda *x:None,lambda:False)
            assert dest.read_bytes()==DATA and Handler.ranges[-1]==123456
            assert not dest.with_name('file.part.json').exists()
            try: dav.get(e,dest,lambda *x:None,lambda:False)
            except ValueError: pass
            else: raise AssertionError('Existing destination must be preserved')
    finally: server.shutdown(); server.server_close()

def test_tui_and_recursive_selection():
    class Fake:
        def list(self,path):
            return [m.Entry('/folder','folder',True)] if path=='/' else [m.Entry('/folder/a','a',False,4)]
        def get(self,e,target,update,cancelled):
            target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes(b'test'); update(4,4,0); return True
    async def check():
        with TemporaryDirectory() as directory:
            app=m.CloudApp(Fake())
            async with app.run_test(size=(120,35)) as pilot:
                await pilot.pause(.3); app.query_one(m.DataTable).focus()
                await pilot.press('space'); assert len(app.selected)==1
                app.query_one('#destination',m.Input).value=directory
                app.action_download()
                for _ in range(60):
                    await pilot.pause(.05)
                    if not app.downloading: break
                assert (Path(directory)/'folder/a').read_bytes()==b'test'
                assert app.total==4
                assert not app.selected
                folder_row = app.query_one(m.DataTable).get_row('/folder')
                assert folder_row[1].style == '#7f8793'
                assert folder_row[-1].plain == 'Скачана'
                app.action_open()
                await pilot.pause(.2)
                assert app.query_one(m.DataTable).get_row('/folder/a')[1].style == '#7f8793'
    asyncio.run(check())

def test_ui_progressive_disclosure(tmp_path):
    class Fake:
        def list(self, path): return []
    async def check():
        app=m.CloudApp(Fake())
        async with app.run_test(size=(80,24)) as pilot:
            await pilot.pause(.2)
            assert not app.query_one('#credentials',m.Vertical).has_class('open')
            table=app.query_one(m.DataTable)
            assert table.region.height >= 16
            assert table.styles.scrollbar_size_vertical == 1
            assert app.query_one('#download',m.Button).region.height == 1
            await pilot.click('#toggle-credentials'); await pilot.pause(.3)
            assert app.query_one('#credentials',m.Vertical).has_class('open')
            assert table.region.height >= 10
            assert app.query_one('#save-credentials',m.Button).region.bottom <= 24
            await pilot.click('#toggle-credentials'); await pilot.pause(.3)
            assert not app.query_one('#credentials',m.Vertical).has_class('open')
            app.query_one('#destination',m.Input).focus()
            await pilot.press('ctrl+u')
            destination = str(tmp_path / 'download-test')
            await pilot.press(*destination)
            assert app.query_one('#destination',m.Input).value == destination
            app.states={'/a':[20,100,0,'Скачивается','']}
            app.downloading=True
            app.progress(); await pilot.pause()
            block=app.query_one('#transfer')
            assert block.region.height <= 5
            assert block.region.contains_region(app.query_one('#bar').region)
            assert block.region.contains_region(app.query_one('#transfer-status').region)
            await pilot.click('#pause-download'); assert app.paused
            await pilot.click('#stop-download'); assert app.stop.is_set()
            app.downloading=False
    asyncio.run(check())

def test_selection_capacity_and_eta(tmp_path, monkeypatch):
    from types import SimpleNamespace
    free = [500]
    disks = []
    def disk_usage(path):
        disks.append(path)
        return SimpleNamespace(free=free[0])
    monkeypatch.setattr(m.shutil, 'disk_usage', disk_usage)
    class Fake:
        def list(self, path):
            if path == '/folder':
                return [m.Entry('/folder/a','a',False,400), m.Entry('/folder/nested','nested',True)]
            if path == '/folder/nested': return [m.Entry('/folder/nested/b','b',False,200)]
            return []
    async def check():
        app=m.CloudApp(Fake())
        async with app.run_test(size=(100,28)) as pilot:
            await pilot.pause(.2)
            app.query_one('#destination',m.Input).value=str(tmp_path/'new'/'child')
            app.selected={'/folder':m.Entry('/folder','folder',True), '/folder/a':m.Entry('/folder/a','a',False,400)}
            app.update_summary()
            await pilot.pause(.3)
            assert app.selection_stats == (2,600,0)  # Nested selection counted once.
            info=app.query_one('#selection-info',m.Static)
            assert info.has_class('insufficient')
            await pilot.pause(.3)  # Disk probe runs outside the UI thread.
            assert disks[-1] == tmp_path  # Target does not exist yet.
            assert 'Не хватает' in str(info.render())
            app.measured_speed=200
            app.render_selection()
            assert '≈ 3 с' in str(info.render())
            free[0]=900
            app.query_one('#destination',m.Input).value=str(tmp_path/'another')
            await pilot.pause(.2)
            assert not info.has_class('insufficient')
            assert 'Запас 300.0 B' in str(info.render())
            app.selected={'/unknown':m.Entry('/unknown','unknown',False)}
            app.update_summary()
            assert 'размер неполный' in str(info.render())
            assert 'Запас' not in str(info.render())
            app.selected.clear(); app.update_summary()
            assert not info.has_class('active')
    asyncio.run(check())

def test_selection_scan_uses_supplied_dav_client():
    calls=[]
    class Fake:
        def list(self, path):
            calls.append(path)
            return [m.Entry('/folder/a','a',False,8)] if path == '/folder' else []
    async def check():
        app=m.CloudApp(Fake())
        async with app.run_test(size=(100,28)) as pilot:
            await pilot.pause(.2)
            app.selected={'/folder':m.Entry('/folder','folder',True)}
            app.update_summary(); await pilot.pause(.4)
            assert app.selection_stats == (1,8,0)
            assert calls == ['/', '/folder']
    asyncio.run(check())

def test_selection_scan_does_not_restore_stale_choice():
    entered=threading.Event(); release=threading.Event()
    class Fake:
        def list(self,path):
            if path == '/slow':
                entered.set(); release.wait(5)
                return [m.Entry('/slow/a','a',False,900)]
            return []
    async def check():
        app=m.CloudApp(Fake())
        async with app.run_test(size=(100,28)) as pilot:
            await pilot.pause(.2)
            app.selected={'/slow':m.Entry('/slow','slow',True)}
            app.update_summary()
            await asyncio.to_thread(entered.wait,2)
            assert entered.is_set()
            app.selected={'/new':m.Entry('/new','new',False,10)}
            app.update_summary()
            release.set()
            await pilot.pause(.2)
            assert app.selection_stats==(1,10,0)
            app.selected.clear(); app.update_summary()
            assert not app.query_one('#selection-info').has_class('active')
    try: asyncio.run(check())
    finally: release.set()

def test_large_selection_roots():
    files = [m.Entry(f'/folder/f{i}', f'f{i}', False, i) for i in range(23425)]
    assert m.selection_roots(files) == files
    folder = m.Entry('/folder', 'folder', True)
    sibling = m.Entry('/folder-other/file', 'file', False, 1)
    assert m.selection_roots(files + [folder, sibling]) == [folder, sibling]


def test_directory_index_shares_inflight_request_and_retries_failure():
    entered, release = threading.Event(), threading.Event()
    calls = []
    entry = m.Entry('/folder/a', 'a', False, 8)
    class Fake:
        def list(self, path):
            calls.append(path)
            entered.set()
            assert release.wait(3)
            if len(calls) == 1: raise m.requests.ReadTimeout('slow folder')
            return [entry]
    index = m.DirectoryIndex(Fake())
    with m.ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(index.list, '/folder')
        assert entered.wait(2)
        # Observe the second caller waiting on the same request deterministically.
        waiting = threading.Event()
        original_result = index.pending['/folder'].result
        def wait_for_result(*args, **kwargs):
            waiting.set()
            return original_result(*args, **kwargs)
        with patch.object(index.pending['/folder'], 'result', wait_for_result):
            second = pool.submit(index.list, '/folder')
            try:
                assert waiting.wait(2)
            finally:
                release.set()
            for future in (first, second):
                with pytest.raises(m.requests.ReadTimeout): future.result(2)
    assert calls == ['/folder']
    assert index.list('/folder') == (entry,)
    assert index.list('/folder') == (entry,)
    assert calls == ['/folder', '/folder']


def test_partial_scan_resumes_for_download_without_relisting_successes(tmp_path):
    calls = []
    folder = m.Entry('/folder', 'folder', True)
    class Fake:
        def list(self, path):
            calls.append(path)
            if path == '/': return [folder]
            if path == '/folder':
                return [m.Entry('/folder/slow', 'slow', True), m.Entry('/folder/a', 'a', False, 4)]
            if calls.count('/folder/slow') == 1: raise m.requests.ReadTimeout('slow folder')
            return [m.Entry('/folder/slow/b', 'b', False, 4)]
        def get(self, entry, target, update, cancelled):
            target.write_bytes(b'test')
            update(4, 4, 0)
            return True
    async def check():
        app = m.CloudApp(Fake())
        async with app.run_test(size=(100, 28)) as pilot:
            await pilot.pause(.2)
            app.selected = {folder.href: folder}
            app.update_summary()
            for _ in range(40):
                await pilot.pause(.05)
                if app.selection_error: break
            assert app.selection_stats == (1, 4, 0)
            assert not app.selection_complete
            text = str(app.query_one('#selection-info').render())
            assert 'Подсчёт не завершён' in text and 'найдено 1 файлов' in text
            assert 'Запас' not in text and 'Выбрано:' not in text
            app.query_one('#destination', m.Input).value = str(tmp_path)
            app.action_download()
            for _ in range(60):
                await pilot.pause(.05)
                if not app.downloading: break
            assert not app.downloading
            assert (tmp_path / 'folder/a').read_bytes() == b'test'
            assert (tmp_path / 'folder/slow/b').read_bytes() == b'test'
            assert calls.count('/folder') == 1
            assert calls.count('/folder/slow') == 2
            assert not app.selected
    asyncio.run(check())


def test_listing_snapshot_refresh_and_account_change():
    folder = m.Entry('/folder', 'folder', True)
    class Fake:
        def __init__(self, volume): self.volume = volume; self.calls = []
        def list(self, path):
            self.calls.append(path)
            return [folder] if path == '/' else [m.Entry('/folder/a', 'a', False, self.volume)]
    async def check():
        dav = Fake(8)
        app = m.CloudApp(dav)
        async with app.run_test(size=(100, 28)) as pilot:
            await pilot.pause(.2)
            app.selected = {folder.href: folder}
            app.update_summary()
            await pilot.pause(.2)
            assert app.selection_complete and app.selection_stats == (1, 8, 0)
            app.action_open()
            await pilot.pause(.2)
            assert app.entries[0].bytes == 8
            assert dav.calls == ['/', '/folder']
            dav.volume = 16
            app.action_refresh()
            await pilot.pause(.2)
            assert app.entries[0].bytes == 16
            assert app.selection_stats == (1, 16, 0)
            assert dav.calls.count('/folder') == 2
            app.dav = Fake(32)
            app.update_summary()
            await pilot.pause(.2)
            assert app.selection_stats == (1, 32, 0)
            assert app.dav.calls == ['/folder']
    asyncio.run(check())

def test_private_credentials_form(tmp_path, monkeypatch):
    monkeypatch.setattr(m, 'PRIVATE_CREDENTIALS', tmp_path / 'config' / 'credentials.enc')
    class Fake:
        def list(self, path): return []
    monkeypatch.setattr(m.DAV, 'list', Fake().list)
    async def check():
        app=m.CloudApp(None)
        async with app.run_test(size=(120,35)) as pilot:
            app.query_one('#user',m.Input).value='person@example.com'
            app.query_one('#key',m.Input).value='private-key'
            app.query_one('#master',m.Input).value='master password for tests'
            await pilot.click('#toggle-credentials'); await pilot.pause()
            await pilot.click('#save-credentials'); await pilot.pause(.2)
            stored=m.PRIVATE_CREDENTIALS.read_text()
            assert 'person@example.com' not in stored and 'private-key' not in stored
            assert m.unlock_config('master password for tests')['MAIL_CLOUD_WEBDAV_KEY']=='private-key'
            assert app.query_one('#master',m.Input).value==''
            if m.os.name != 'nt':
                assert (m.PRIVATE_CREDENTIALS.stat().st_mode & 0o777) == 0o600
                assert (m.PRIVATE_CREDENTIALS.parent.stat().st_mode & 0o777) == 0o700
            assert app.query_one('#key',m.Input).password
            assert app.query_one('#user',m.Input).password
            assert isinstance(app.dav, m.DAV)
    asyncio.run(check())

def test_encryption_rejects_wrong_password_and_tampering(tmp_path, monkeypatch):
    import pytest
    monkeypatch.setattr(m,'PRIVATE_CREDENTIALS',tmp_path/'private'/'credentials.enc')
    m.save_config('user@example.com','test-secret','long master password')
    with pytest.raises(ValueError): m.unlock_config('wrong master password')
    payload=json.loads(m.PRIVATE_CREDENTIALS.read_text())
    ciphertext=bytearray(m.base64.b64decode(payload['ciphertext'])); ciphertext[0]^=1
    payload['ciphertext']=m.base64.b64encode(ciphertext).decode()
    m.PRIVATE_CREDENTIALS.write_text(json.dumps(payload))
    with pytest.raises(ValueError): m.unlock_config('long master password')


@contextmanager
def http_server(handler):
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with patch.object(m, 'BASE', f'http://127.0.0.1:{server.server_port}/'):
            yield
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_dav_special_names_and_propstats():
    class DAVHandler(BaseHTTPRequestHandler):
        xml = b'''<d:multistatus xmlns:d="DAV:"><d:response><d:href>/</d:href></d:response>
        <d:response><d:href>/a%23b%3Fc%3Bd%2520.txt</d:href>
        <d:propstat><d:prop><d:resourcetype/><d:getcontentlength>8</d:getcontentlength></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
        <d:propstat><d:prop><d:getetag>"v1"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
        <d:propstat><d:prop><d:creationdate>unavailable</d:creationdate></d:prop><d:status>HTTP/1.1 404 Not Found</d:status></d:propstat>
        </d:response></d:multistatus>'''
        def log_message(self, *args): pass
        def do_PROPFIND(self):
            assert self.headers['Depth'] == '1'
            self.send_response(207)
            self.send_header('Content-Length', str(len(self.xml)))
            self.end_headers()
            self.wfile.write(self.xml)
    with http_server(DAVHandler):
        dav = m.DAV('test', 'key')
        entry, = dav.list()
        assert entry.href == '/a#b?c;d%20.txt'
        assert entry.bytes == 8 and entry.etag == '"v1"' and not entry.created
        assert dav.url(entry.href) == m.BASE + 'a%23b%3Fc%3Bd%2520.txt'
        DAVHandler.xml = DAVHandler.xml.replace(b'/a%23b%3Fc%3Bd%2520.txt', b'/other/child')
        with pytest.raises(ValueError, match='вне'): dav.list()


def test_large_dav_listing_recovers_from_read_timeout(monkeypatch):
    # A real HTTP response stalls after its headers, as requests may report the
    # body read timeout as ConnectionError rather than ReadTimeout.
    count = 23425
    xml = ('<d:multistatus xmlns:d="DAV:">' + ''.join(
        f'<d:response><d:href>/large/f{i}</d:href><d:propstat><d:prop>'
        f'<d:resourcetype/><d:getcontentlength>{i}</d:getcontentlength>'
        '</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>'
        for i in range(count)) + '</d:multistatus>').encode()
    release = threading.Event()
    class SlowDAV(BaseHTTPRequestHandler):
        calls = 0
        def log_message(self, *args): pass
        def do_PROPFIND(self):
            # Drain the request body before closing, or TCP may reset a large reply.
            self.rfile.read(int(self.headers.get('Content-Length', '0')))
            type(self).calls += 1
            first = type(self).calls == 1
            self.send_response(207)
            self.send_header('Content-Length', str(len(xml)))
            self.end_headers()
            if first:
                release.wait(3)
                return
            self.wfile.write(xml)
    monkeypatch.setattr(m.time, 'sleep', lambda _: None)
    with http_server(SlowDAV):
        dav = m.DAV('test', 'key')
        original = dav._list
        timeouts = []
        def short_timeout(path, timeout):
            timeouts.append(timeout)
            return original(path, .03 if len(timeouts) == 1 else 5)
        monkeypatch.setattr(dav, '_list', short_timeout)
        try:
            index = m.DirectoryIndex(dav)
            entries = index.list('/large')
            assert len(entries) == count
            assert sum(e.bytes for e in entries) == count * (count - 1) // 2
            assert len({e.href for e in entries}) == count
            assert index.list('/large') is entries
            assert SlowDAV.calls == 2 and timeouts == [30, 60]
        finally:
            release.set()


@pytest.mark.parametrize('status, attempts', [(503, 3), (429, 3), (401, 1), (403, 1), (404, 1)])
def test_dav_listing_retry_limit_and_permanent_errors(monkeypatch, status, attempts):
    response = m.requests.Response()
    response.status_code = status
    error = m.requests.HTTPError('test failure', response=response)
    dav = m.DAV('test', 'key')
    monkeypatch.setattr(m.time, 'sleep', lambda _: None)
    with patch.object(dav, '_list', side_effect=error) as request:
        with pytest.raises(m.requests.HTTPError): dav.list('/folder')
        assert request.call_count == attempts


@pytest.mark.parametrize('href', ['/../x', '/%2e%2e/x', '/a//b', '/x%5Cy', '/x%00y', 'https://example.invalid/file', '/x?query', '/x#fragment'])
def test_dav_rejects_unsafe_paths(href):
    with pytest.raises(ValueError): m.remote_path(href)


@pytest.mark.parametrize('separator', [' ', '='])
def test_resume_rejects_other_account_and_invalid_range(tmp_path, separator):
    class InvalidRange(Handler):
        def do_GET(self):
            if self.headers.get('Range'):
                self.send_response(206)
                self.send_header('Content-Range', f'bytes{separator}0-{len(DATA)-1}/{len(DATA)}')
                self.send_header('Content-Length', str(len(DATA)))
                self.end_headers()
                return
            super().do_GET()
    with http_server(InvalidRange):
        entry = m.Entry('/file', 'file', False, len(DATA), etag='"v1"')
        dest = tmp_path / 'file'
        cancelled = threading.Event()
        dav = m.DAV('first', 'test')
        assert not dav.get(entry, dest, lambda *args: cancelled.set(), cancelled.is_set)
        partial = dest.with_name('file.part')
        partial.write_bytes(DATA[:100])
        with pytest.raises(ValueError, match='другой версии'):
            m.DAV('second', 'test').get(entry, dest, lambda *args: None, lambda: False)
        with pytest.raises(ValueError, match='Content-Range'):
            dav.get(entry, dest, lambda *args: None, lambda: False)
        assert partial.read_bytes() == DATA[:100] and not dest.exists()


@pytest.mark.parametrize('separator', [' ', '='])
def test_resume_accepts_valid_standard_and_mail_content_range(tmp_path, separator):
    observed = []
    class MailRange(Handler):
        def send_header(self, name, value):
            if name == 'Content-Range': value = value.replace('bytes ', 'bytes' + separator)
            super().send_header(name, value)
        def do_GET(self):
            observed.append(self.headers.get('Range'))
            super().do_GET()
    with http_server(MailRange):
        entry = m.Entry('/file', 'file', False, len(DATA), etag='"v1"')
        target = tmp_path / 'file'
        dav = m.DAV('test', 'key')
        stop = threading.Event()
        assert not dav.get(entry, target, lambda *args: stop.set(), stop.is_set)
        partial = target.with_name('file.part')
        partial.write_bytes(DATA[:123456])
        assert dav.get(entry, target, lambda *args: None, lambda: False)
        assert observed == [None, 'bytes=123456-']
        assert target.read_bytes() == DATA
        assert not partial.exists()


def test_complete_partial_is_revalidated(tmp_path):
    class Conditional(Handler):
        def do_GET(self):
            assert self.headers.get('If-Match') == '"v1"'
            if getattr(self.server, 'changed', False):
                self.send_response(412)
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
            super().do_GET()
    with http_server(Conditional):
        dest = tmp_path / 'file'
        entry = m.Entry('/file', 'file', False, len(DATA), etag='"v1"')
        cancelled = threading.Event()
        dav = m.DAV('test', 'key')
        dav.get(entry, dest, lambda *args: cancelled.set(), cancelled.is_set)
        partial = dest.with_name('file.part')
        partial.write_bytes(DATA)
        original = Conditional.do_GET
        def changed(self):
            self.server.changed = True
            original(self)
        with patch.object(Conditional, 'do_GET', changed):
            with pytest.raises(m.requests.HTTPError):
                dav.get(entry, dest, lambda *args: None, lambda: False)
        assert partial.read_bytes() == DATA and not dest.exists()


def test_destination_lock_and_atomic_publication(tmp_path, monkeypatch):
    with m.destination_lock(tmp_path):
        with pytest.raises(ValueError):
            with m.destination_lock(tmp_path): pass
    with m.destination_lock(tmp_path): pass
    partial, target = tmp_path / 'file.part', tmp_path / 'file'
    partial.write_bytes(b'complete')
    target.write_bytes(b'existing')
    with pytest.raises(FileExistsError): m.publish_partial(partial, target)
    assert target.read_bytes() == b'existing' and partial.read_bytes() == b'complete'
    target.unlink()
    if m.os.name != 'nt':
        def unsupported(*args): raise OSError(errno.EOPNOTSUPP, 'No hard links')
        with monkeypatch.context() as patcher:
            patcher.setattr(m.os, 'link', unsupported)
            with pytest.raises(OSError): m.publish_partial(partial, target)
        assert not target.exists() and partial.read_bytes() == b'complete'
    m.publish_partial(partial, target)
    assert target.read_bytes() == b'complete' and not partial.exists()


@pytest.mark.parametrize('payload', [[], None, {'version': 1}, {'version': 1, 'kdf': 'scrypt-n32768-r8-p1', 'salt': [], 'nonce': None, 'ciphertext': 3}])
def test_malformed_vault_is_reported(tmp_path, monkeypatch, payload):
    vault = tmp_path / 'credentials.enc'
    vault.write_text(json.dumps(payload), encoding='utf-8')
    vault.chmod(0o600)
    monkeypatch.setattr(m, 'PRIVATE_CREDENTIALS', vault)
    with pytest.raises(ValueError, match='Не удалось расшифровать'):
        m.unlock_config('long test master password')


def test_credentials_path_respects_user_config(tmp_path, monkeypatch):
    monkeypatch.setattr(m.Path, 'home', classmethod(lambda cls: tmp_path / 'home'))
    variable = 'APPDATA' if m.os.name == 'nt' else 'XDG_CONFIG_HOME'
    monkeypatch.setenv(variable, str(tmp_path / 'user config'))
    assert m.credentials_path() == tmp_path / 'user config' / 'cloudmailru' / 'credentials.enc'
    monkeypatch.setenv(variable, 'relative-path')
    assert m.credentials_path().is_absolute()
    legacy = tmp_path / 'home' / '.config' / 'cloudmailru' / 'credentials.enc'
    legacy.parent.mkdir(parents=True)
    legacy.write_text('legacy', encoding='utf-8')
    assert m.credentials_path() == legacy


def test_failed_navigation_has_no_stale_entries():
    class Fake:
        def list(self, path):
            if path != '/': raise OSError('offline')
            return [m.Entry('/folder', 'folder', True)]
    async def check():
        app = m.CloudApp(Fake())
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause(.2)
            app.action_open()
            await pilot.pause(.2)
            assert app.path == '/folder' and not app.entries
            assert 'offline' in str(app.query_one('#hint').render())
            app.action_back()
            await pilot.pause(.2)
            assert app.path == '/' and len(app.entries) == 1
    asyncio.run(check())


@pytest.mark.parametrize('name', ['file:stream', 'NUL', 'con.txt', 'file.', 'file ', 'a?b', 'a*b'])
def test_windows_invalid_names_fail_explicitly(name):
    with pytest.raises(ValueError, match='Windows'):
        m.validate_local_name(name, windows=True)
    m.validate_local_name(name, windows=False)


def test_disk_probe_does_not_block_ui(tmp_path, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    def slow_disk(path):
        entered.set()
        assert release.wait(5)
        return type('Usage', (), {'free': 1000})()
    monkeypatch.setattr(m.shutil, 'disk_usage', slow_disk)
    class Fake:
        def list(self, path): return []
    async def check():
        app = m.CloudApp(Fake())
        async with app.run_test(size=(80, 24)) as pilot:
            app.query_one('#destination', m.Input).value = str(tmp_path)
            app.selected = {'/file': m.Entry('/file', 'file', False, 10)}
            app.update_summary()
            assert await asyncio.to_thread(entered.wait, 2)
            await pilot.click('#toggle-credentials')
            assert app.query_one('#credentials').has_class('open')
            release.set()
            await pilot.pause(.2)
            assert app.disk_free == 1000
    try:
        asyncio.run(check())
    finally:
        release.set()


@pytest.mark.parametrize('names', [('File', 'file'), ('caf\u00e9', 'cafe\u0301'), ('file', 'FILE.PART'), ('file', 'FILE.PART.JSON')])
def test_alias_collisions_fail_before_download(tmp_path, names):
    calls = []
    class Fake:
        def list(self, path): return []
        def get(self, *args): calls.append(args)
    async def check():
        app = m.CloudApp(Fake())
        async with app.run_test(size=(100, 28)) as pilot:
            app.query_one('#destination', m.Input).value = str(tmp_path)
            app.selected = {'/'+n: m.Entry('/'+n, n, False, 10) for n in names}
            app.action_download()
            for _ in range(40):
                await pilot.pause(.05)
                if not app.downloading: break
            assert not app.downloading
            assert not calls
            assert 'конфликт' in str(app.query_one('#transfer-status').render()).lower()
            assert list(tmp_path.iterdir()) == [tmp_path / '.cloudmail-download.lock']
    asyncio.run(check())


def test_completed_rows_clear_selection_and_keep_cursor(tmp_path):
    entries = [m.Entry('/'+name, name, False, 4, etag='"v1"')
               for name in ('done', 'failed', 'stopped')]
    class Fake:
        def list(self, path): return entries[:]
        def get(self, entry, target, update, cancelled):
            if entry.name == 'failed': raise OSError('test failure')
            if entry.name == 'stopped': return False
            target.write_bytes(b'done')
            update(4, 4, 0)
            return True
    async def check():
        app = m.CloudApp(Fake())
        async with app.run_test(size=(100, 28)) as pilot:
            await pilot.pause(.2)
            app.selected = {e.href:e for e in entries}
            app.refresh_table()
            table = app.query_one(m.DataTable)
            table.move_cursor(row=2)
            table.focus()
            app.query_one('#destination', m.Input).value = str(tmp_path)
            app.action_download()
            for _ in range(60):
                await pilot.pause(.05)
                if not app.downloading: break
            assert not app.downloading
            assert app.selected.keys() == {'/failed', '/stopped'}
            assert table.cursor_row == 2
            assert all(cell.style == '#7f8793' for cell in table.get_row('/done'))
            assert table.get_row('/done')[0].plain == ' '
            assert table.get_row('/failed')[0].plain == '✓'
            assert table.get_row('/failed')[1].style == ''
            assert table.get_row('/stopped')[1].style == ''
            app.action_refresh()
            await pilot.pause(.2)
            assert table.get_row('/done')[1].style == '#7f8793'
            # A completed file can still be explicitly selected for another copy.
            table.move_cursor(row=0)
            app.action_toggle()
            assert '/done' in app.selected
            # A new cloud version must not inherit the old completion colour.
            entries[0] = m.Entry('/done', 'done', False, 5, etag='"v2"')
            app.action_refresh()
            await pilot.pause(.2)
            assert table.get_row('/done')[1].style == ''
    asyncio.run(check())
