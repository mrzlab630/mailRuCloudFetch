import asyncio
import json
import threading
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
            await pilot.click('#save-credentials'); await pilot.pause(.2)
            stored=m.PRIVATE_CREDENTIALS.read_text()
            assert 'person@example.com' not in stored and 'private-key' not in stored
            assert m.unlock_config('master password for tests')['MAIL_CLOUD_WEBDAV_KEY']=='private-key'
            assert app.query_one('#master',m.Input).value==''
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
