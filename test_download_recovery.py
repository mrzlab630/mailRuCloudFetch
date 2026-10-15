import asyncio
import threading
from collections import Counter

import pytest

import cloudmail_downloader as m
from test_downloader import DATA, Handler, http_server


async def wait_for_batch(app, pilot):
    for _ in range(100):
        await pilot.pause(.05)
        if not app.downloading:
            await pilot.pause(.1)
            return
    raise AssertionError('Download did not finish')


def test_error_dialog_first_pass_single_selected_and_all_retries(tmp_path, monkeypatch):
    monkeypatch.setattr(m, 'RETRY_DELAYS', (0, 0, 0, 0))
    entries = [m.Entry('/folder/' + name, name, False, 4) for name in ('good', 'one', 'two', 'three', 'denied')]
    folder = m.Entry('/folder', 'folder', True)
    calls = Counter()
    class Fake:
        def list(self, path): return [folder] if path == '/' else entries
        def get(self, entry, target, update, cancelled, read_timeout=30):
            calls[entry.name] += 1
            if entry.name == 'denied': raise PermissionError('read-only destination')
            if entry.name != 'good' and calls[entry.name] == 1:
                target.with_name(target.name + '.part').write_bytes(b'ab')
                raise m.requests.ReadTimeout('body stalled')
            if entry.name != 'good': assert read_timeout == 90
            assert target == tmp_path / 'folder' / entry.name
            update(2 if entry.name != 'good' else 0, 4, 0)
            target.write_bytes(b'done')
            update(4, 4, 1)
            return True
    async def check():
        app = m.CloudApp(Fake())
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause(.2)
            app.selected = {folder.href: folder}
            app.query_one('#destination', m.Input).value = str(tmp_path)
            app.update_summary()
            app.action_download()
            await wait_for_batch(app, pilot)
            assert calls == Counter({e.name: 1 for e in entries})
            assert isinstance(app.screen, m.ErrorRetryScreen)
            screen = app.screen
            assert set(screen.order) == {e.href for e in entries if e.name != 'good'}
            assert app.states['/folder/one'][0] == 2
            assert '/folder' in app.selected
            for selector in ('#retry-current', '#retry-selected', '#retry-all', '#close-errors', '#retry-stop'):
                assert screen.query_one('#error-dialog').region.contains_region(screen.query_one(selector).region)
            # Search and filter preserve the original folder navigation and selection.
            screen.query_one('#error-search', m.Input).value = 'denied'
            await pilot.pause(.1)
            assert screen.order == ['/folder/denied']
            assert 'read-only destination' in str(screen.query_one('#error-details').render())
            screen.query_one('#error-search', m.Input).value = ''
            screen.query_one('#error-filter', m.Select).value = 'temporary'
            await pilot.pause(.1)
            assert screen.order == ['/folder/one', '/folder/three', '/folder/two']
            assert app.path == '/'
            await pilot.press('escape')
            assert not isinstance(app.screen, m.ErrorRetryScreen)
            assert app.query_one('#show-errors', m.Button).display
            # Retry stays bound to the original destination, even after the input changes.
            app.query_one('#destination', m.Input).value = str(tmp_path / 'another')
            await pilot.click('#show-errors')
            screen = app.screen
            table = screen.query_one('#error-table', m.DataTable)
            table.move_cursor(row=screen.order.index('/folder/one'))
            await pilot.click('#retry-current')
            await wait_for_batch(app, pilot)
            assert calls['one'] == 2 and calls['two'] == calls['three'] == calls['good'] == 1
            assert screen is app.screen
            assert app.states['/folder/one'][3] == 'Готово'
            assert '/folder/one' in screen.order  # Successful recovery remains in the report.
            table.move_cursor(row=screen.order.index('/folder/two'))
            table.focus()
            await pilot.press('space')
            assert screen.checked == {'/folder/two'}
            await pilot.click('#retry-selected')
            await wait_for_batch(app, pilot)
            assert calls['two'] == 2 and calls['three'] == 1
            await pilot.click('#retry-all')
            await wait_for_batch(app, pilot)
            assert calls['three'] == 2 and calls['good'] == calls['denied'] == 1
            assert 'Готово: 3' in str(screen.query_one('#error-summary').render())
            # A permanent error can be retried manually after correction, only once.
            table.move_cursor(row=screen.order.index('/folder/denied'))
            await pilot.click('#retry-current')
            await wait_for_batch(app, pilot)
            assert calls['denied'] == 2 and app.retry_attempts['/folder/denied'] == 1
            assert '/folder' in app.selected
            assert not (tmp_path / 'another').exists()
    asyncio.run(check())


def test_retry_limit_and_stop_interrupts_backoff_and_pending_files(tmp_path, monkeypatch):
    monkeypatch.setattr(m, 'RETRY_DELAYS', (0, 0, 0, 0))
    entries = [m.Entry('/' + name, name, False, 4) for name in ('one', 'two')]
    calls = Counter()
    class Fake:
        def list(self, path): return entries
        def get(self, entry, target, update, cancelled, read_timeout=30):
            calls[entry.name] += 1
            raise m.requests.ConnectionError('offline')
    async def check():
        app = m.CloudApp(Fake())
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause(.2)
            app.query_one('#destination', m.Input).value = str(tmp_path)
            app.selected = {entry.href: entry for entry in entries}
            app.action_download()
            await wait_for_batch(app, pilot)
            app.start_error_retry(['/one', '/one'])
            await wait_for_batch(app, pilot)
            assert calls == Counter(one=6, two=1)
            assert app.retry_attempts['/one'] == 5
            assert app.states['/one'][3] == 'Ошибка'
            monkeypatch.setattr(m, 'RETRY_DELAYS', (60, 60, 60, 60))
            app.start_error_retry(['/one', '/two'])
            for _ in range(40):
                await pilot.pause(.05)
                if app.states['/one'][3].startswith('Повтор через'): break
            assert app.downloading
            assert app.states['/one'][3].startswith('Повтор через')
            await pilot.click('#retry-stop')
            await wait_for_batch(app, pilot)
            assert calls == Counter(one=7, two=1)
            assert all(app.states[e.href][3] == 'Остановлено' for e in entries)
            assert isinstance(app.screen, m.ErrorRetryScreen)
    asyncio.run(check())


def test_user_stop_does_not_create_error_report(tmp_path):
    started = threading.Event()
    tick = threading.Event()
    folder = m.Entry('/folder', 'folder', True)
    entries = [m.Entry('/folder/file', 'file', False, 4)]

    class Fake:
        def list(self, path):
            return [folder] if path == '/' else entries

        def get(self, entry, target, update, cancelled, read_timeout=30):
            started.set()
            while not cancelled():
                tick.wait(.01)
            return False

    async def check():
        app = m.CloudApp(Fake())
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause(.2)
            app.query_one('#destination', m.Input).value = str(tmp_path)
            app.selected = {folder.href: folder}
            app.action_download()
            assert await asyncio.to_thread(started.wait, 2)
            app.action_stop()
            await wait_for_batch(app, pilot)
            await pilot.pause(.1)
            assert app.states['/folder/file'][3] == 'Остановлено'
            assert app.error_jobs == {}
            assert not app.query_one('#show-errors', m.Button).display
            assert not isinstance(app.screen, m.ErrorRetryScreen)
            assert 'Ошибок: 0' in str(app.query_one('#transfer-status', m.Static).render())
            assert '/folder' in app.selected

    asyncio.run(check())


def test_retry_resumes_real_partial_without_recounting_and_clears_folder(tmp_path):
    offset = 256 * 1024
    requests_seen = []
    timeouts = []
    class Interrupted(Handler):
        def do_GET(self):
            requests_seen.append(self.headers.get('Range'))
            if len(requests_seen) == 1:
                self.send_response(200)
                self.send_header('Content-Length', str(len(DATA)))
                self.send_header('ETag', '"v1"')
                self.end_headers()
                self.wfile.write(DATA[:offset])
                return
            super().do_GET()
    folder = m.Entry('/folder', 'folder', True)
    entry = m.Entry('/folder/file', 'file', False, len(DATA), etag='"v1"')
    with http_server(Interrupted):
        dav = m.DAV('test', 'key')
        dav.list = lambda path: [folder] if path == '/' else [entry]
        original_get = dav.get
        def get(*args, **kwargs):
            timeouts.append(kwargs.get('read_timeout', 30))
            return original_get(*args, **kwargs)
        dav.get = get
        async def check():
            app = m.CloudApp(dav)
            async with app.run_test(size=(120, 35)) as pilot:
                await pilot.pause(.2)
                app.query_one('#destination', m.Input).value = str(tmp_path)
                app.selected = {folder.href: folder}
                app.action_download()
                await wait_for_batch(app, pilot)
                partial = tmp_path / 'folder/file.part'
                assert partial.read_bytes() == DATA[:offset]
                assert app.states[entry.href][0] == offset
                assert app.received == offset
                app.screen.action_retry_all()
                await wait_for_batch(app, pilot)
                assert requests_seen == [None, f'bytes={offset}-']
                assert timeouts == [30, 90]
                assert (tmp_path / 'folder/file').read_bytes() == DATA
                assert not partial.exists()
                assert app.received == len(DATA)  # Resume offset must not be added twice.
                assert not app.selected
                assert isinstance(app.screen, m.ErrorRetryScreen)
                assert 'Готово: 1' in str(app.screen.query_one('#error-summary').render())
        asyncio.run(check())


@pytest.mark.parametrize('status,expected', [(408, True), (429, True), (500, True), (502, True), (503, True),
                                           (504, True), (401, False), (403, False), (404, False), (412, False), (416, False)])
def test_download_http_error_classification(status, expected):
    response = m.requests.Response()
    response.status_code = status
    assert m.retryable_download_error(m.requests.HTTPError(response=response)) is expected


@pytest.mark.parametrize('error,expected', [(m.requests.ReadTimeout(), True), (m.requests.ConnectTimeout(), True),
    (m.requests.ConnectionError(), True), (m.requests.exceptions.ChunkedEncodingError(), True),
    (m.requests.exceptions.SSLError(), False), (PermissionError(), False), (ValueError('version changed'), False)])
def test_download_error_classification(error, expected):
    assert m.retryable_download_error(error) is expected


def test_careful_http_timeout_profile(tmp_path, monkeypatch):
    observed = []
    original = m.requests.get
    def get(*args, **kwargs):
        observed.append(kwargs['timeout'])
        return original(*args, **kwargs)
    monkeypatch.setattr(m.requests, 'get', get)
    with http_server(Handler):
        entry = m.Entry('/file', 'file', False, len(DATA), etag='"v1"')
        dav = m.DAV('test', 'key')
        assert dav.get(entry, tmp_path / 'normal', lambda *args: None, lambda: False)
        assert dav.get(entry, tmp_path / 'careful', lambda *args: None, lambda: False, read_timeout=90)
    assert observed == [(15, 30), (30, 90)]
