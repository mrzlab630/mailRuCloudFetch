#!/usr/bin/env python3
"""Cloud.Mail.ru WebDAV TUI downloader."""
from __future__ import annotations
import asyncio, base64, json, os, re, shutil, stat, sys, tempfile, time, threading, webbrowser, xml.etree.ElementTree as ET
import hashlib
import ntpath
import unicodedata
from rich.text import Text
from contextlib import contextmanager
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from urllib.parse import quote, unquote, urlsplit
import requests
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from textual.app import App, ComposeResult
from textual.screen import ModalScreen
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Input, Label, ProgressBar, Select, Static, DataTable, Button
from textual import work

BASE = "https://webdav.cloud.mail.ru/"
RETRY_DELAYS = (5, 15, 30, 60)
__version__ = "1.6.0"
def credentials_path():
    if os.name == 'nt':
        directory = Path(os.environ.get('APPDATA') or Path.home() / 'AppData' / 'Roaming')
    else:
        directory = Path(os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config')
    if not directory.is_absolute(): directory = Path.home() / ('.config' if os.name != 'nt' else 'AppData/Roaming')
    # Preserve existing vaults if XDG_CONFIG_HOME was introduced later.
    legacy = Path.home() / '.config' / 'cloudmailru' / 'credentials.enc'
    return legacy if legacy.exists() or legacy.is_symlink() else directory / 'cloudmailru' / 'credentials.enc'

PRIVATE_CREDENTIALS = credentials_path()
PROPFIND = b'''<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/><d:getcontentlength/><d:getlastmodified/><d:creationdate/><d:getcontenttype/><d:getetag/></d:prop></d:propfind>'''

def current_user_owns(path):
    return os.name == 'nt' or getattr(os, 'getuid', lambda: path.stat().st_uid)() == path.stat().st_uid

def restrictive_mode_ok(path):
    return os.name == 'nt' or not (path.stat().st_mode & 0o077)

def config():
    d = {}
    p = Path(__file__).with_name('.env')
    if p.exists():
        for line in p.read_text(encoding='utf-8').splitlines():
            if '=' in line and not line.lstrip().startswith('#'):
                k, v = line.split('=', 1); d[k.strip()] = v.strip().strip("'\"")
    for k in ('MAIL_CLOUD_USER', 'MAIL_CLOUD_WEBDAV_KEY'):
        d[k] = os.getenv(k, d.get(k, ''))
    return d

def _derive(master: str, salt: bytes) -> bytes:
    if not master or len(master) < 12:
        raise ValueError('Мастер-пароль должен содержать минимум 12 символов')
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(master.encode('utf-8'))

def save_config(user: str, key: str, master: str):
    if not user or not key or any(c in user + key for c in ('\n', '\r', '\x00')):
        raise ValueError('Логин и ключ не должны содержать переносы строк или пустые значения')
    if not master or len(master) < 12:
        raise ValueError('Мастер-пароль должен содержать минимум 12 символов')
    PRIVATE_CREDENTIALS.parent.mkdir(parents=True, exist_ok=True)
    directory = PRIVATE_CREDENTIALS.parent.lstat()
    if PRIVATE_CREDENTIALS.parent.is_symlink() or not stat.S_ISDIR(directory.st_mode) or not current_user_owns(PRIVATE_CREDENTIALS.parent):
        raise ValueError('Приватный каталог должен принадлежать вам и не быть symlink')
    os.chmod(PRIVATE_CREDENTIALS.parent, 0o700)
    if PRIVATE_CREDENTIALS.is_symlink():
        raise ValueError('Symlink вместо приватного файла запрещён')
    salt, nonce = os.urandom(16), os.urandom(12)
    aad = b'cloudmailru-credentials-v1'
    plaintext = json.dumps({'user': user, 'key': key}, ensure_ascii=False, separators=(',', ':')).encode()
    encrypted = AESGCM(_derive(master, salt)).encrypt(nonce, plaintext, aad)
    payload = {'version': 1, 'kdf': 'scrypt-n32768-r8-p1', 'salt': base64.b64encode(salt).decode(), 'nonce': base64.b64encode(nonce).decode(), 'ciphertext': base64.b64encode(encrypted).decode()}
    fd, temporary = tempfile.mkstemp(dir=PRIVATE_CREDENTIALS.parent, prefix='.credentials-', text=True)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            os.chmod(temporary, 0o600)
            stream.write(json.dumps(payload, ensure_ascii=False, indent=2) + '\n')
            stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, PRIVATE_CREDENTIALS)
    finally:
        Path(temporary).unlink(missing_ok=True)

def unlock_config(master: str) -> dict[str, str]:
    if not PRIVATE_CREDENTIALS.exists():
        raise FileNotFoundError(f'Зашифрованное хранилище не найдено: {PRIVATE_CREDENTIALS}')
    info = PRIVATE_CREDENTIALS.lstat()
    if not stat.S_ISREG(info.st_mode) or not current_user_owns(PRIVATE_CREDENTIALS) or not restrictive_mode_ok(PRIVATE_CREDENTIALS):
        raise ValueError('Зашифрованный файл должен принадлежать вам и иметь права 0600')
    try:
        payload = json.loads(PRIVATE_CREDENTIALS.read_text(encoding='utf-8'))
        if not isinstance(payload,dict) or payload.get('version') != 1 or payload.get('kdf') != 'scrypt-n32768-r8-p1': raise ValueError('Неподдерживаемая версия хранилища')
        salt = base64.b64decode(payload['salt'],validate=True); nonce = base64.b64decode(payload['nonce'],validate=True); ciphertext = base64.b64decode(payload['ciphertext'],validate=True)
        if len(salt)!=16 or len(nonce)!=12: raise ValueError('Повреждённое хранилище')
        raw = AESGCM(_derive(master, salt)).decrypt(nonce, ciphertext, b'cloudmailru-credentials-v1')
        data = json.loads(raw.decode('utf-8'))
        if not isinstance(data,dict) or any(not isinstance(data.get(k),str) or not data[k] for k in ('user','key')): raise ValueError('В хранилище нет полного набора credentials')
        return {'MAIL_CLOUD_USER': data['user'], 'MAIL_CLOUD_WEBDAV_KEY': data['key']}
    except (InvalidTag, KeyError, TypeError, ValueError, UnicodeError) as exc:
        raise ValueError('Не удалось расшифровать credentials: неверный мастер-пароль или повреждённый файл') from exc

def size(n):
    if n is None: return '—'
    x = float(n)
    for u in ('B','KiB','MiB','GiB','TiB'):
        if x < 1024 or u == 'TiB': return f'{x:.1f} {u}'
        x /= 1024

def duration(seconds):
    seconds = max(1, int(seconds + .999))
    if seconds < 60: return f'{seconds} с'
    minutes = (seconds + 59) // 60
    if minutes < 60: return f'{minutes} мин'
    hours, minutes = divmod(minutes, 60)
    return f'{hours} ч {minutes:02d} мин'

def remote_path(href):
    """Decode a DAV href once; internal paths are decoded, never parsed as URLs."""
    parsed = urlsplit(href)
    if parsed.netloc and (parsed.scheme,parsed.netloc) != (urlsplit(BASE).scheme,urlsplit(BASE).netloc):
        raise ValueError('Посторонний сервер в WebDAV href')
    if parsed.query or parsed.fragment: raise ValueError('Некорректный WebDAV href')
    path = unquote(parsed.path,errors='strict').rstrip('/') or '/'
    if not path.startswith('/') or any(p in ('.','..','') for p in path[1:].split('/') if path != '/') or any(ord(c)<32 or c=='\\' for c in path):
        raise ValueError('Небезопасный путь WebDAV')
    return path

def validate_local_name(name, windows=None):
    windows = os.name == 'nt' if windows is None else windows
    if not name or name in ('.','..') or any(c in name for c in ('/', '\\', '\x00')):
        raise ValueError('Небезопасное имя локального файла')
    if windows and (name.endswith((' ','.')) or getattr(ntpath,'isreserved',lambda value: PureWindowsPath(value).is_reserved())(name)
                    or any(ord(c)<32 or c in '<>:"|?*' for c in name)):
        raise ValueError('Имя файла не поддерживается Windows; переименуйте объект в облаке')

def local_path_key(path):
    # Reject aliases conservatively, including on case-sensitive hosts.
    return unicodedata.normalize('NFC', str(path.resolve())).casefold()

@contextmanager
def destination_lock(destination):
    """Coordinate cooperating processes without deleting the lock inode."""
    destination.mkdir(parents=True,exist_ok=True)
    path=destination/'.cloudmail-download.lock'
    if path.is_symlink(): raise ValueError('Symlink вместо файла блокировки')
    fd=os.open(path,os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode): raise ValueError('Некорректный файл блокировки')
        try:
            if os.name=='nt':
                import msvcrt
                if os.fstat(fd).st_size == 0: os.write(fd,b'0')
                os.lseek(fd,0,os.SEEK_SET)
                msvcrt.locking(fd,msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError: raise ValueError('Папка занята или файловая система не поддерживает блокировку') from None
        yield
    finally: os.close(fd)

def publish_partial(part,target):
    """Publish without overwriting or exposing a partially copied final file."""
    if os.name == 'nt':
        os.rename(part,target)  # Windows rename refuses an existing destination.
        return
    os.link(part,target)  # Unsupported filesystems retain the complete .part.
    part.unlink()

@dataclass(frozen=True)
class Entry:
    href: str; name: str; directory: bool; bytes: int|None = None
    modified: str = ''; created: str = ''; content_type: str = ''; etag: str = ''

def selection_roots(picked):
    directories = {e.href for e in picked if e.directory}
    return [e for e in picked if not any(str(parent) in directories for parent in PurePosixPath(e.href).parents)]

class DirectoryIndex:
    """Share complete directory listings and in-flight requests for one snapshot."""
    def __init__(self, dav):
        self.dav = dav
        self.entries = {}
        self.pending = {}
        self.lock = threading.Lock()

    def list(self, path):
        with self.lock:
            if path in self.entries: return self.entries[path]
            future = self.pending.get(path)
            owner = future is None
            if owner:
                future = Future()
                self.pending[path] = future
        if not owner: return future.result()
        try:
            entries = tuple(self.dav.list(path))
        except BaseException as exc:
            with self.lock:
                del self.pending[path]
                future.set_exception(exc)
            raise
        with self.lock:
            self.entries[path] = entries
            del self.pending[path]
            future.set_result(entries)
        return entries

class DAV:
    def __init__(self, user, key):
        self.auth = (user, key)
    def url(self, href):
        if not href.startswith('/') or href.startswith('//'): raise ValueError('Ожидался абсолютный путь в облаке')
        return BASE.rstrip('/') + quote(href, safe='/')
    def list(self, path='/'):
        # A slow collection must not discard every directory already scanned.
        # Retry only transient failures, with more time for large PROPFIND replies.
        for attempt, read_timeout in enumerate((30, 60, 120)):
            try:
                return self._list(path, read_timeout)
            except requests.HTTPError as exc:
                if exc.response is None or exc.response.status_code not in (429, 500, 502, 503, 504): raise
                if attempt == 2: raise
            except (requests.Timeout, requests.ConnectionError, requests.exceptions.ChunkedEncodingError):
                if attempt == 2: raise
            time.sleep(attempt + 1)

    def _list(self, path, read_timeout):
        path=path.rstrip('/') or '/'
        with requests.request('PROPFIND',self.url(path),auth=self.auth,data=PROPFIND,headers={'Depth':'1','Content-Type':'application/xml'},timeout=(15,read_timeout),allow_redirects=False) as r:
            r.raise_for_status()
            if r.status_code != 207: raise ValueError(f'PROPFIND HTTP {r.status_code}, ожидался 207')
            root=ET.fromstring(r.content)
        if root.tag != '{DAV:}multistatus': raise ValueError('Некорректный WebDAV XML')
        result={}
        for node in root.findall('{DAV:}response'):
            href=remote_path(node.findtext('{DAV:}href',''))
            if href==path: continue
            if str(PurePosixPath(href).parent)!=path: raise ValueError('WebDAV вернул объект вне запрошенной папки')
            props={}
            for propstat in node.findall('{DAV:}propstat'):
                if ' 200 ' in propstat.findtext('{DAV:}status',''):
                    p=propstat.find('{DAV:}prop')
                    if p is not None: props.update({c.tag:c for c in p})
            resource=props.get('{DAV:}resourcetype')
            if resource is None: raise ValueError('WebDAV не предоставил тип объекта; обновите каталог')
            def value(name):
                p=props.get('{DAV:}'+name)
                return (p.text or '') if p is not None else ''
            raw=value('getcontentlength')
            result[href]=Entry(href,PurePosixPath(href).name,resource.find('{DAV:}collection') is not None,int(raw) if raw.isdigit() else None,value('getlastmodified'),value('creationdate'),value('getcontenttype'),value('getetag'))
        return sorted(result.values(), key=lambda x:(not x.directory,x.name.casefold()))
    def get(self, entry, target, update, cancelled, read_timeout=30):
        if cancelled(): return False
        validate_local_name(target.name)
        if target.exists() or target.is_symlink(): raise ValueError('Файл уже существует; выберите другую папку назначения')
        target.parent.mkdir(parents=True, exist_ok=True); part = target.with_name(target.name+'.part'); meta=target.with_name(target.name+'.part.json')
        if part.is_symlink() or meta.is_symlink(): raise ValueError('Symlink вместо .part запрещён')
        if any(p.exists() and not p.is_file() for p in (part,meta)):
            raise ValueError('Вместо .part или .part.json найден не обычный файл')
        identity={'path':entry.href,'size':entry.bytes,'etag':entry.etag,'modified':entry.modified,
                  'source':hashlib.sha256((BASE+'\n'+self.auth[0]).encode()).hexdigest()}
        done=0
        if part.exists():
            if not meta.exists() or json.loads(meta.read_text(encoding='utf-8')) != identity: raise ValueError('Частичный файл другой версии; переместите его перед повтором')
            done=part.stat().st_size
        elif meta.exists(): raise ValueError('Существующий .part.json не принадлежит этой загрузке')
        if entry.bytes is not None and done > entry.bytes: raise ValueError('Частичный файл больше исходного')
        validator=entry.etag if entry.etag and not entry.etag.startswith('W/') else entry.modified
        headers={'Accept-Encoding':'identity'}
        if done and validator and done != entry.bytes: headers.update({'Range':f'bytes={done}-','If-Range':validator})
        else: done=0
        if entry.etag and not entry.etag.startswith('W/'): headers['If-Match']=entry.etag
        elif entry.modified: headers['If-Unmodified-Since']=entry.modified
        # Per-transfer sessions avoid sharing mutable requests state across threads.
        with requests.get(self.url(entry.href),auth=self.auth,headers=headers,stream=True,timeout=(30 if read_timeout > 30 else 15,read_timeout),allow_redirects=False) as r:
            r.raise_for_status()
            if r.status_code == 200:
                done=0
                total=int(r.headers['Content-Length']) if 'Content-Length' in r.headers else entry.bytes
            elif r.status_code == 206:
                match=re.fullmatch(r'bytes (\d+)-(\d+)/(\d+)',r.headers.get('Content-Range',''))
                if 'Range' not in headers or not match or int(match[1]) != done or int(match[2]) != int(match[3])-1: raise ValueError('Некорректный Content-Range')
                total=int(match[3])
                if 'Content-Length' in r.headers and int(r.headers['Content-Length']) != total-done: raise ValueError('Content-Length не соответствует Content-Range')
            else: raise ValueError(f'GET HTTP {r.status_code}')
            if r.headers.get('Content-Encoding','identity') != 'identity': raise ValueError('Сжатый поток не поддерживает безопасное возобновление')
            if entry.bytes is not None and total != entry.bytes: raise ValueError('Размер изменился; обновите каталог')
            if entry.etag and r.headers.get('ETag') and entry.etag != r.headers['ETag']: raise ValueError('Версия изменилась; обновите каталог')
            meta.write_text(json.dumps(identity),encoding='utf-8'); started=time.monotonic(); initial=done
            update(done,total,0)
            with part.open('ab' if done else 'wb') as f:
                for chunk in r.iter_content(256*1024):
                    if cancelled(): return False
                    if chunk: f.write(chunk); done += len(chunk); update(done,total,(done-initial)/max(time.monotonic()-started,.001))
                f.flush(); os.fsync(f.fileno())
        if total is not None and done != total: raise ValueError('Файл неполный; повторите загрузку')
        if cancelled(): return False
        publish_partial(part,target); meta.unlink(); return True

def retryable_download_error(exc):
    if isinstance(exc, requests.exceptions.SSLError): return False
    if isinstance(exc, (requests.Timeout, requests.ConnectionError, requests.exceptions.ChunkedEncodingError)):
        return True
    if isinstance(exc, requests.HTTPError) and exc.response is not None:
        return exc.response.status_code in (408, 429, 500, 502, 503, 504)
    return False

class ErrorRetryScreen(ModalScreen):
    """Review failed files after a batch and retry selected transient failures."""
    BINDINGS = [
        ('space', 'toggle_row', 'Отметить'),
        ('r', 'retry_current', 'Повторить'),
        ('a', 'retry_all', 'Повторить временные'),
        ('x', 'stop_retry', 'Стоп'),
        ('q', 'quit_app', 'Выход'),
        ('escape', 'close', 'Закрыть'),
    ]
    def __init__(self, app):
        super().__init__()
        self.owner = app
        self.order = []
        self.checked = set()
        self.rows = {}

    def compose(self):
        with Vertical(id='error-dialog'):
            yield Static('Ошибки загрузки', id='error-title', markup=False)
            yield Static('', id='error-summary', markup=False)
            with Horizontal(id='error-filter-row'):
                yield Input(placeholder='Поиск по пути или ошибке', id='error-search')
                yield Select([('Все', 'all'), ('Временные', 'temporary'), ('Требуют внимания', 'attention'),
                              ('Готово', 'done'), ('Остановлено', 'stopped')], value='all', allow_blank=False, id='error-filter')
            yield DataTable(cursor_type='row', id='error-table')
            yield Static('', id='error-details', markup=False)
            yield Static('Бережно: 1 поток · чтение 90 с · до 5 попыток · продолжение .part', id='error-profile', markup=False)
            with Horizontal(id='error-actions'):
                yield Button('Повторить файл', id='retry-current')
                yield Button('Повторить отмеченные', id='retry-selected', variant='primary')
                yield Button('Повторить временные', id='retry-all')
            with Horizontal(id='error-footer'):
                yield Button('Стоп', id='retry-stop')
                yield Button('Закрыть', id='close-errors')

    def on_mount(self):
        table = self.query_one('#error-table', DataTable)
        for label, key, width in [(' ', 'check', 1), ('Файл', 'file', max(12, min(44, self.size.width - 68))),
                                  ('Причина', 'error', 14), ('Сохранено', 'saved', 17), ('Статус', 'status', 15)]:
            table.add_column(label, key=key, width=width)
        self.refresh_rows()
        self.query_one('#error-table', DataTable).focus()
        self.set_interval(.3, self.refresh_rows)

    def refresh_rows(self):
        table = self.query_one('#error-table', DataTable)
        if not table.columns: return
        with self.owner.lock:
            jobs = dict(self.owner.error_jobs)
            states = {href: self.owner.states[href][:] for href in jobs}
            retryable = dict(self.owner.error_retryable)
            messages = dict(self.owner.error_messages)
            attempts = dict(self.owner.retry_attempts)
        self.checked.intersection_update(href for href in jobs if states[href][3] != 'Готово')
        search = self.query_one('#error-search', Input).value.casefold()
        mode = self.query_one('#error-filter', Select).value
        rows = {}
        for href, (entry, target) in jobs.items():
            state = states[href]
            done, total, _speed, status, message = state
            total = total if total is not None else entry.bytes
            label = messages.get(href, message) or status
            if search not in (href + ' ' + label).casefold(): continue
            if mode == 'temporary' and (not retryable.get(href) or status == 'Готово'): continue
            if mode == 'attention' and (retryable.get(href) or status != 'Ошибка'): continue
            if mode == 'done' and status != 'Готово': continue
            if mode == 'stopped' and status != 'Остановлено': continue
            attempt = f' · {attempts[href]}/5' if attempts.get(href) else ''
            rows[href] = ('✓' if href in self.checked else ' ', href, label,
                          f'{size(done)} / {size(total)}', status + attempt)
        order = sorted(rows)
        if order != self.order:
            current = self.current_href()
            table.clear()
            self.order = order
            for href in order:
                table.add_row(*(Text(value) for value in rows[href]), key=href)
            if current in order: table.move_cursor(row=order.index(current))
        else:
            for href in order:
                for column, value, old in zip(table.columns, rows[href], self.rows.get(href, ('',) * 5)):
                    if value != old: table.update_cell(href, column, Text(value))
        self.rows = rows
        complete = sum(state[3] == 'Готово' for state in states.values())
        errors = sum(state[3] == 'Ошибка' for state in states.values())
        stopped = sum(state[3] == 'Остановлено' for state in states.values())
        active = len(states) - complete - errors - stopped
        self.query_one('#error-summary', Static).update(
            f'Готово: {complete} · ошибок: {errors} · стоп: {stopped} · в работе: {active} · отмечено: {len(self.checked)}',
        )
        for button in ('retry-current', 'retry-selected', 'retry-all'):
            self.query_one('#' + button, Button).disabled = self.owner.downloading
        self.query_one('#retry-stop', Button).disabled = not self.owner.downloading
        if self.order:
            self.show_current()
        else:
            self.query_one('#error-details', Static).update('Нет файлов для выбранного фильтра.')

    def current_href(self):
        table = self.query_one('#error-table', DataTable)
        row = table.cursor_row
        return self.order[row] if row is not None and 0 <= row < len(self.order) else None

    def show_current(self):
        href = self.current_href() or (self.order[0] if self.order else None)
        if href not in self.owner.error_jobs: return
        entry, target = self.owner.error_jobs[href]
        state = self.owner.states.get(href, [0, entry.bytes, 0, 'Ошибка', ''])
        retry = 'временная ошибка' if self.owner.error_retryable.get(href, False) else 'сначала исправьте причину'
        if state[3] == 'Готово': retry = 'восстановлено'
        elif state[3] == 'Остановлено': retry = 'можно продолжить'
        self.query_one('#error-details', Static).update(
            f'{entry.href}\nЛокальный путь: {target}\n{self.owner.error_messages.get(href) or state[3]} · {retry}',
        )

    def on_data_table_row_highlighted(self, event):
        event.stop()
        self.show_current()

    def on_data_table_row_selected(self, event):
        event.stop()
        self.action_toggle_row()

    def on_input_changed(self, event):
        event.stop()
        if self.is_mounted: self.refresh_rows()

    def on_select_changed(self, event):
        event.stop()
        if self.is_mounted: self.refresh_rows()

    def action_toggle_row(self):
        if not isinstance(self.focused, DataTable): return
        href = self.current_href()
        if href is None or self.owner.states[href][3] == 'Готово': return
        if href in self.checked: self.checked.remove(href)
        else: self.checked.add(href)
        self.refresh_rows()

    def retry_jobs(self, hrefs):
        if self.owner.downloading: return
        self.owner.start_error_retry(hrefs)
        self.refresh_rows()

    def action_retry_current(self): self.retry_jobs([self.current_href()])
    def action_retry_all(self):
        self.retry_jobs([href for href in self.owner.error_jobs if self.owner.error_retryable.get(href)])
    def action_stop_retry(self): self.owner.action_stop()
    def action_close(self): self.dismiss()
    async def action_quit_app(self): await self.owner.action_quit()

    def on_button_pressed(self, event):
        event.stop()
        actions = {
            'retry-current': self.action_retry_current,
            'retry-selected': lambda: self.retry_jobs(sorted(self.checked)),
            'retry-all': self.action_retry_all,
            'retry-stop': self.action_stop_retry,
            'close-errors': self.action_close,
        }
        action = actions.get(event.button.id)
        if action: action()

class CloudApp(App):
    CSS = '''
    Screen { background: #10151b; }
    Screen { overflow: hidden; scrollbar-size: 1 1; }
    Button { height: 1; min-width: 0; width: auto; border: none; padding: 0 1; background: #202c38; }
    Button:hover { background: #304759; }
    Button:focus { text-style: bold underline; }
    #toolbar { height: 1; padding: 0 1; background: #151b23; }
    #toolbar Button { margin-left: 1; }
    #summary { width: 1fr; height: 1; color: $text-muted; }
    #destination-row { height: 1; margin: 1 1 0 1; }
    #destination-label { width: 19; height: 1; }
    Input { height: 1; border: none; padding: 0 1; background: #19232d; }
    Input:focus { border: none; background: #263848; }
    #credentials { display: none; height: 6; margin: 0 1; padding: 0; background: #151b23; }
    #credentials.open { display: block; }
    #credentials Horizontal { height: 1; margin: 0; }
    #credentials Label { width: 19; height: 1; }
    #credentials Button { margin-right: 1; }
    #destination { width: 1fr; }
    #threads { width: 14; height: 1; border: none; margin-left: 1; }
    #threads SelectCurrent { height: 1; border: none; padding: 0; }
    #user, #key, #master { width: 1fr; }
    DataTable { height: 1fr; min-height: 4; margin: 1 1 0 1; scrollbar-size: 1 1; }
    #details { height: 1; padding: 0 1; color: $text-muted; }
    #selection-info { display: none; height: auto; max-height: 3; padding: 0 1; color: $text-muted; }
    #selection-info.active { display: block; }
    #selection-info.insufficient { color: $error; }
    #hint { height: auto; max-height: 2; padding: 0 1; color: $text-muted; }
    #transfer { display: none; height: auto; max-height: 5; margin: 0 1; background: #19232d; }
    #transfer.active { display: block; }
    #transfer-status { height: auto; max-height: 3; }
    #transfer-controls { height: 1; }
    #bar { height: 1; width: 1fr; }
    #show-errors { display: none; }
    ErrorRetryScreen { align: center middle; background: #000000 65%; }
    #error-dialog { width: 96%; height: 94%; max-width: 150; border: round #526a80; padding: 0 1; background: #151b23; }
    #error-title { height: 1; text-style: bold; }
    #error-summary { height: 1; }
    #error-filter-row { height: 1; margin-top: 1; }
    #error-search { width: 1fr; }
    #error-filter { width: 24; height: 1; border: none; margin-left: 1; }
    #error-filter SelectCurrent { height: 1; border: none; padding: 0; }
    #error-table { margin: 1 0 0 0; min-height: 3; }
    #error-details { height: 4; margin-top: 1; overflow-y: auto; }
    #error-profile { height: 1; color: $text-muted; }
    #error-actions, #error-footer { height: 1; margin-top: 1; }
    #error-actions Button, #error-footer Button { margin-right: 1; }
    '''
    BINDINGS = [('q','quit','Выход'),('space','toggle','Выбрать'),('enter','open','Открыть'),('d','download','Скачать'),('b','back','Назад'),('o','browser','Браузер'),('r','refresh','Обновить'),('x','stop','Стоп'),('p','pause','Пауза')]
    def __init__(self, dav, credentials=None):
        super().__init__(); self.dav=dav; self.credentials=credentials or {}; self.path='/'; self.entries=[]; self.selected={}; self.dest=Path.cwd()/'downloads'; self.jobs=[]; self.total=0; self.done=0; self.speed=0
        self.states={}; self.lock=threading.RLock(); self.stop=threading.Event(); self.paused=False; self.downloading=False; self.received=0; self.sample=(time.monotonic(),0)
        self.selection_signature = None
        self.selection_stats = None
        self.selection_complete = False
        self.selection_error = ''
        self.selection_generation = 0
        self.listings = DirectoryIndex(dav)
        self.measured_speed = 0.0
        self.rate_sample = (time.monotonic(), 0)
        self.disk_signature = None
        self.disk_free = None
        self.disk_pending = False
        self.disk_checked = 0.0
        self.downloaded = {}  # Published file versions, for this account/session.
        self.error_jobs = {}
        self.error_retryable = {}
        self.error_messages = {}
        self.retry_attempts = {}
        self.batch_picked = []
        self.batch_destination = None
        self.batch_dav = None
        self.quitting = False
    def compose(self)->ComposeResult:
        with Horizontal(id='toolbar'):
            yield Static('',id='summary',markup=False)
            yield Button('Скачать',id='download',variant='primary')
            yield Button('Доступ',id='toggle-credentials')
            yield Button('Обновить',id='refresh')
        with Horizontal(id='destination-row'):
            yield Label('Папка назначения',id='destination-label')
            yield Input(str(self.dest),placeholder='Введите путь',id='destination')
            yield Select([(f'{n} потоков',n) for n in (1,2,4,8,16)],value=4,allow_blank=False,id='threads')
        with Vertical(id='credentials'):
            yield Static('Доступ · данные хранятся зашифрованно',markup=False)
            with Horizontal():
                yield Label('Логин Mail')
                yield Input(self.credentials.get('MAIL_CLOUD_USER',''),password=True,id='user')
            with Horizontal():
                yield Label('WebDAV ключ')
                yield Input(self.credentials.get('MAIL_CLOUD_WEBDAV_KEY',''),password=True,id='key')
            with Horizontal():
                yield Label('Мастер-пароль')
                yield Input('',placeholder='Минимум 12 символов',password=True,id='master')
            with Horizontal(id='credential-actions'):
                yield Button('Сохранить зашифрованно',id='save-credentials')
                yield Button('Расшифровать',id='unlock-credentials')
        yield DataTable(cursor_type='row',id='table')
        yield Static('',id='details',markup=False)
        yield Static('',id='selection-info',markup=False)
        with Vertical(id='transfer'):
            yield Static('',id='transfer-status',markup=False)
            with Horizontal(id='transfer-controls'):
                yield ProgressBar(total=100,show_eta=False,show_percentage=False,id='bar')
                yield Button('Пауза',id='pause-download')
                yield Button('Стоп',id='stop-download')
                yield Button('Ошибки',id='show-errors')
        yield Static('',id='hint',markup=False)
        yield Footer()
    def on_mount(self):
        self.title='MAIL CLOUD · WebDAV'; self.set_interval(.25,self.progress)
        self.update_summary()
        if self.dav is not None: self.load()
        else: self.query_one('#hint',Static).update('Откройте «Доступ», чтобы разблокировать или сохранить credentials')
    def update_summary(self):
        if self.listings.dav is not self.dav:
            self.listings = DirectoryIndex(self.dav)
        self.query_one('#summary', Static).update(f'{self.path}  ·  выбрано {len(self.selected)}')
        signature = (id(self.dav), tuple(self.selected.values()))
        if signature != self.selection_signature:
            self.selection_signature = signature
            self.selection_generation += 1
            self.selection_stats = None
            self.selection_complete = False
            self.selection_error = ''
            picked = list(self.selected.values())
            if any(e.directory for e in picked):
                self.scan_selection(picked, self.listings, self.selection_generation)
            else:
                self.selection_stats = (len(picked), sum(e.bytes or 0 for e in picked), sum(e.bytes is None for e in picked))
                self.selection_complete = True
        self.render_selection()

    @work(exclusive=True, group='selection-size')
    async def scan_selection(self, picked, scanner, generation):
        total = files = unknown = 0
        stack = selection_roots(picked)
        seen = set()
        try:
            while stack:
                if generation != self.selection_generation: return
                entry = stack.pop()
                if entry.href in seen: continue
                seen.add(entry.href)
                if entry.directory:
                    self.selection_stats = (files, total, unknown)
                    self.render_selection()
                    stack.extend(await asyncio.to_thread(scanner.list, entry.href))
                else:
                    files += 1
                    total += entry.bytes or 0
                    unknown += entry.bytes is None
                    if files % 256 == 0:
                        self.selection_stats = (files, total, unknown)
                        self.render_selection()
                        await asyncio.sleep(0)
            if generation == self.selection_generation:
                self.selection_stats = (files, total, unknown)
                self.selection_complete = True
        except Exception as exc:
            if generation == self.selection_generation:
                self.selection_stats = (files, total, unknown)
                self.selection_error = self.err(exc)
        if generation == self.selection_generation: self.render_selection()

    def on_input_changed(self, event):
        if event.input.id == 'destination' and self.is_mounted:
            self.render_selection()

    @work(exclusive=True, group='disk-space')
    async def measure_disk_space(self, raw):
        def probe():
            target = Path(raw).expanduser().absolute()
            while not target.exists():
                parent = target.parent
                if parent == target:
                    raise ValueError('Путь назначения недоступен')
                target = parent
            if not target.is_dir():
                raise ValueError('Путь ведёт к файлу')
            return shutil.disk_usage(target).free
        try:
            free = await asyncio.to_thread(probe)
            if self.disk_signature == raw:
                self.disk_free = free
        except (OSError, ValueError, RuntimeError):
            if self.disk_signature == raw:
                self.disk_free = None
        finally:
            if self.disk_signature == raw:
                self.disk_pending = False
                self.disk_checked = time.monotonic()
                self.render_selection()

    def render_selection(self):
        if not self.query('#selection-info'): return  # Timer/worker may finish during teardown.
        widget = self.query_one('#selection-info', Static)
        widget.set_class(bool(self.selected), 'active')
        widget.remove_class('insufficient')
        if not self.selected: return
        raw = self.query_one('#destination', Input).value.strip()
        if raw != self.disk_signature:
            self.disk_signature = raw
            self.disk_free, self.disk_pending, self.disk_checked = None, False, 0.0
        if raw and not self.disk_pending and time.monotonic() - self.disk_checked >= 2:
            self.disk_pending = True
            self.measure_disk_space(raw)
        free = self.disk_free
        disk = f'Свободно: {size(free)}'
        if self.selection_stats is None:
            widget.update(f'Подсчёт выбранных папок… · {disk}')
            return
        files, total, unknown = self.selection_stats
        volume = f'{size(total)}' + (f' + {unknown} без размера' if unknown else '')
        if not self.selection_complete:
            status = 'Подсчёт не завершён' if self.selection_error else 'Подсчёт…'
            widget.update(f'{status} · найдено {files} файлов · {volume}\n{disk}' +
                          (f'\n{self.selection_error}' if self.selection_error else ''))
            return
        if free is not None:
            if total > free:
                disk += f' · Не хватает {size(total-free)}'
                widget.add_class('insufficient')
            elif unknown:
                disk += ' · Размер неполный'
            else:
                disk += f' · Запас {size(free-total)}'
        if unknown: eta = 'Время: размер неполный'
        elif total == 0: eta = 'Время: 0 с'
        elif self.measured_speed > 0:
            eta = f'≈ {duration(total/self.measured_speed)} при {size(self.measured_speed)}/с'
        else: eta = 'Время: после замера скорости'
        widget.update(f'Выбрано: {files} файлов · {volume}\n{disk} · {eta}')
    def err(self,e):
        text = f'Ошибка: {e}'
        for value in self.credentials.values():
            if value: text = text.replace(value, '[скрыто]')
        return text[:200]
    @work(exclusive=True,group='load')
    async def load(self):
        if self.dav is None: return
        dav = self.dav
        listings = self.listings
        path = self.path
        try:
            entries=await asyncio.to_thread(listings.list,path)
            if dav is self.dav and listings is self.listings and path == self.path:
                self.entries=entries
                for e in entries:
                    if e.href in self.selected: self.selected[e.href]=e
                self.selection_signature=None
                self.refresh_table()
        except Exception as e:
            if dav is self.dav and listings is self.listings and path == self.path:
                self.query_one('#hint',Static).update(self.err(e))
    def refresh_table(self):
        self.query_one('#details',Static).update('')
        t=self.query_one(DataTable); t.clear(columns=True); t.add_columns(' ','Имя','Размер','Тип','Создано','Изменено')
        for e in self.entries: t.add_row(*self.entry_cells(e),key=e.href)
        self.update_summary()
        self.query_one('#hint',Static).update('' if self.entries else 'Папка пуста')
    def entry_cells(self, entry):
        complete = not entry.directory and self.downloaded.get(entry.href) == entry
        style = '#7f8793' if complete else ''
        values = ('✓' if entry.href in self.selected else ' ', entry.name,
                  'Папка' if entry.directory else size(entry.bytes),
                  'Папка' if entry.directory else (entry.content_type or Path(entry.name).suffix or 'Файл'),
                  entry.created or '—', entry.modified or '—')
        return [Text(value, style=style) for value in values]

    def mark_downloaded(self, entry):
        """Called on the UI thread only after a file is successfully published."""
        self.downloaded[entry.href] = entry
        if self.selected.get(entry.href) == entry:
            self.selected.pop(entry.href)
        table = self.query_one(DataTable)
        visible = next((e for e in self.entries if e.href == entry.href), None)
        if visible is not None:
            for column, cell in zip(table.columns, self.entry_cells(visible)):
                table.update_cell(entry.href, column, cell)
        self.update_summary()
    def action_toggle(self):
        if isinstance(self.focused,Input): return
        t=self.query_one(DataTable)
        if t.cursor_row is None or t.cursor_row >= len(self.entries): return
        e=self.entries[t.cursor_row]
        if e.href in self.selected: self.selected.pop(e.href)
        else: self.selected[e.href]=e
        t.update_cell(e.href,next(iter(t.columns)),self.entry_cells(e)[0])
        self.update_summary()
    def on_data_table_row_highlighted(self,event):
        if event.cursor_row < len(self.entries):
            self.query_one('#details',Static).update(self.entries[event.cursor_row].name)
    def action_open(self):
        if not self.entries: return
        row = self.query_one(DataTable).cursor_row
        if row is None or row < 0 or row >= len(self.entries): return
        e=self.entries[row]
        if e.directory:
            self.path = e.href
            self.entries = []
            self.refresh_table()
            self.load()
    def on_data_table_row_selected(self,event): self.action_open()
    def action_back(self):
        self.path = str(PurePosixPath(self.path).parent)
        self.entries = []
        self.refresh_table()
        self.load()
    def action_refresh(self):
        self.listings = DirectoryIndex(self.dav)
        self.selection_signature = None
        self.update_summary()
        self.load()
    def action_browser(self):
        row = self.query_one(DataTable).cursor_row
        path=self.entries[row].href if self.entries and row is not None and 0 <= row < len(self.entries) else self.path
        webbrowser.open('https://cloud.mail.ru/home'+quote(path,safe='/')); self.query_one('#hint',Static).update('Открыт путь в веб-интерфейсе Mail Cloud; потребуется вход. Публичная ссылка WebDAV не предоставляется.')
    def action_stop(self): self.stop.set(); self.paused=False
    def action_pause(self): self.paused=not self.paused
    def on_button_pressed(self,event):
        if event.button.id == 'download': self.action_download()
        elif event.button.id == 'save-credentials': self.save_credentials()
        elif event.button.id == 'unlock-credentials': self.unlock_credentials()
        elif event.button.id == 'refresh': self.action_refresh()
        elif event.button.id == 'toggle-credentials': self.toggle_panel('credentials')
        elif event.button.id == 'pause-download': self.action_pause()
        elif event.button.id == 'stop-download': self.action_stop()
        elif event.button.id == 'show-errors': self.action_show_errors()
    def toggle_panel(self, panel_id):
        panel = self.query_one(f'#{panel_id}', Vertical)
        panel.toggle_class('open')
        if not panel.has_class('open'): self.query_one(DataTable).focus()
    def unlock_credentials(self):
        if self.downloading:
            self.notify('Сначала остановите загрузку', severity='warning'); return
        master = self.query_one('#master', Input).value
        try:
            credentials = unlock_config(master)
            self.downloaded.clear()
            self.clear_error_report()
            self.credentials = credentials
            self.dav = DAV(credentials['MAIL_CLOUD_USER'], credentials['MAIL_CLOUD_WEBDAV_KEY'])
            self.query_one('#user', Input).value = credentials['MAIL_CLOUD_USER']
            self.query_one('#key', Input).value = credentials['MAIL_CLOUD_WEBDAV_KEY']
            self.selected.clear(); self.entries=[]; self.states={}; self.path='/'; self.refresh_table(); self.load()
            self.measured_speed=0; self.query_one('#transfer').remove_class('active')
            self.query_one('#hint', Static).update('Credentials расшифрованы только в памяти процесса')
        except (OSError, ValueError) as exc:
            self.query_one('#hint', Static).update(self.err(exc))
        finally:
            self.query_one('#master', Input).value = ''
    def save_credentials(self):
        if self.downloading:
            self.notify('Сначала остановите загрузку и дождитесь завершения потоков', severity='warning')
            return
        user = self.query_one('#user', Input).value.strip()
        key = self.query_one('#key', Input).value
        master = self.query_one('#master', Input).value
        if not user or not key:
            self.query_one('#hint', Static).update('Нужно заполнить логин и WebDAV ключ')
            return
        try:
            save_config(user, key, master)
            self.downloaded.clear()
            self.clear_error_report()
            self.credentials = {'MAIL_CLOUD_USER': user, 'MAIL_CLOUD_WEBDAV_KEY': key}
            self.dav = DAV(user, key)
            self.selected.clear(); self.entries=[]; self.states={}; self.path = '/'; self.refresh_table(); self.load()
            self.measured_speed=0; self.query_one('#transfer').remove_class('active')
            self.update_summary()
            self.query_one('#hint', Static).update('Доступ сохранён зашифрованно. Открываю корень Mail Cloud…')
        except (OSError, ValueError) as exc:
            self.query_one('#hint', Static).update(self.err(exc))
        finally:
            self.query_one('#master', Input).value = ''
    def action_download(self):
        if self.downloading or not self.selected: return
        try:
            raw=self.query_one('#destination',Input).value.strip()
            if not raw: raise ValueError('Укажите папку назначения')
            self.dest=Path(raw).expanduser().resolve()
            if self.dest.exists() and not self.dest.is_dir(): raise ValueError('Путь назначения ведёт к файлу')
        except (OSError,ValueError,RuntimeError) as exc:
            self.query_one('#hint',Static).update(self.err(exc)); return
        self.clear_error_report()
        self.batch_destination = self.dest
        self.batch_dav = self.dav
        self.batch_picked = list(self.selected.values())
        self.jobs = []
        self.downloading=True; self.stop.clear(); self.paused=False; self.states={}; self.received=0; self.sample=(time.monotonic(),0)
        self.rate_sample = self.sample
        self.query_one('#transfer').add_class('active')
        self.query_one('#transfer-status',Static).update('Подсчитываю файлы и общий размер…')
        self.query_one('#bar',ProgressBar).update(progress=0)
        self.download_batch(list(self.selected.values()),self.query_one('#threads',Select).value,self.listings)
    @work(thread=True,group='downloads')
    def download_batch(self,picked,threads,listings):
        try:
            with destination_lock(self.dest): self.run_download_batch(picked,threads,listings)
        except Exception as exc:
            self.call_from_thread(self.query_one('#transfer-status',Static).update,self.err(exc))
        finally:
            self.call_from_thread(self.finish_download)

    def run_download_batch(self,picked,threads,listings):
        try:
            self.call_from_thread(self.query_one('#transfer-status',Static).update,'Подсчитываю файлы и общий размер…')
            jobs=[]; directories=[]; seen=set(); targets=set()
            roots=selection_roots(picked)
            stack=[(e,self.dest/e.name) for e in roots]
            scanned_bytes = 0
            reported = time.monotonic()
            while stack:
                if self.stop.is_set():
                    self.call_from_thread(self.query_one('#transfer-status',Static).update,'Остановлено'); return
                e,target=stack.pop()
                if e.href in seen: continue
                seen.add(e.href)
                validate_local_name(e.name)
                if not target.resolve().is_relative_to(self.dest.resolve()): raise ValueError('Путь назначения выходит за выбранную папку')
                target_key=local_path_key(target)
                if target_key in targets or target.name.casefold() == '.cloudmail-download.lock': raise ValueError('Конфликт путей назначения (регистр или Unicode)')
                targets.add(target_key)
                if e.directory or time.monotonic() - reported >= .25:
                    self.call_from_thread(self.query_one('#transfer-status',Static).update,
                                          f'Подсчёт… найдено {len(jobs)} файлов · {size(scanned_bytes)}')
                    reported = time.monotonic()
                if e.directory:
                    directories.append(target); stack.extend((c,target/c.name) for c in listings.list(e.href))
                else:
                    jobs.append((e,target))
                    scanned_bytes += e.bytes or 0
            self.total=sum(e.bytes or 0 for e,t in jobs)
            reserved=set()
            directory_keys={local_path_key(d) for d in directories}
            for e,t in jobs:
                for p in (t,t.with_name(t.name+'.part'),t.with_name(t.name+'.part.json')):
                    key=local_path_key(p)
                    if key in reserved or key in directory_keys: raise ValueError('Имена файлов конфликтуют с .part; выберите файлы отдельно')
                    reserved.add(key)
            with self.lock: self.states={e.href:[0,e.bytes,0,'Ожидает',''] for e,t in jobs}
            self.jobs = jobs
            for d in directories: d.mkdir(parents=True,exist_ok=True)
            if not jobs:
                self.call_from_thread(self.query_one('#transfer-status',Static).update,'Готово: пустые папки созданы, файлов нет')
            with ThreadPoolExecutor(max_workers=threads) as pool:
                futures=[pool.submit(self.download_one,e,t) for e,t in jobs]
                for f in futures: f.result()
            successful_folders = [e for e in picked if e.directory and all(
                self.states[file.href][3] == 'Готово'
                for file, _ in jobs if file.href.startswith(e.href.rstrip('/')+'/'))]
            self.call_from_thread(self.clear_completed_folders, successful_folders)
        except Exception as exc:
            self.call_from_thread(self.query_one('#transfer-status',Static).update,self.err(exc))
    def download_one(self,e,target,careful=False):
        def cancelled():
            while self.paused and not self.stop.is_set(): self.stop.wait(.1)
            return self.stop.is_set()
        previous=[None]
        def up(done,total,speed):
            with self.lock:
                if previous[0] is not None: self.received+=max(0,done-previous[0])
                previous[0]=done; self.states[e.href]=[done,total,speed,'Скачивается','']
        for attempt in range(5 if careful else 1):
            try:
                if cancelled():
                    self.record_stopped(e,target)
                    return
                if careful:
                    with self.lock: self.retry_attempts[e.href] = attempt + 1
                previous[0] = None  # Resumed bytes are progress, not newly received traffic.
                options = {'read_timeout': 90} if careful else {}
                ok=self.dav.get(e,target,up,cancelled,**options)
                with self.lock:
                    self.states[e.href][3]='Готово' if ok else 'Остановлено'
                    self.states[e.href][2]=0
                    self.states[e.href][4]=''
                if ok: self.call_from_thread(self.mark_downloaded,e)
                else: self.record_stopped(e,target)
                return
            except Exception as ex:
                part = target.with_name(target.name+'.part')
                try:
                    info = part.lstat()
                    saved = info.st_size if stat.S_ISREG(info.st_mode) else 0
                except OSError: saved = 0
                temporary = retryable_download_error(ex)
                with self.lock:
                    self.states[e.href][0]=saved
                    self.states[e.href][2:]=[0,'Ошибка',self.err(ex)]
                    self.error_jobs[e.href]=(e,target)
                    self.error_retryable[e.href]=temporary
                    self.error_messages[e.href]=self.err(ex)
                if self.stop.is_set():
                    self.record_stopped(e,target)
                    return
                if not careful or not temporary or attempt == 4: return
                delay = RETRY_DELAYS[attempt]
                with self.lock: self.states[e.href][3]=f'Повтор через {delay} с'
                if self.stop.wait(delay):
                    self.record_stopped(e,target)
                    return

    def record_stopped(self, entry, target):
        with self.lock:
            self.states[entry.href][2:]=[0,'Остановлено','']
            self.error_jobs[entry.href]=(entry,target)
            self.error_retryable.setdefault(entry.href,False)
            self.error_messages.setdefault(entry.href,'Остановлено пользователем')

    def clear_error_report(self):
        with self.lock:
            self.error_jobs.clear()
            self.error_retryable.clear()
            self.error_messages.clear()
            self.retry_attempts.clear()
        self.query_one('#show-errors',Button).display=False

    def finish_download(self):
        self.downloading=False
        self.query_one('#show-errors',Button).display=bool(self.error_jobs)
        if self.error_jobs and not self.stop.is_set() and not self.quitting: self.action_show_errors()

    def action_show_errors(self):
        if self.error_jobs and not isinstance(self.screen,ErrorRetryScreen):
            self.push_screen(ErrorRetryScreen(self))

    def start_error_retry(self, hrefs):
        with self.lock:
            if self.downloading or self.dav is not self.batch_dav: return
            jobs=[self.error_jobs[href] for href in dict.fromkeys(hrefs)
                  if href in self.error_jobs and self.states[href][3] in ('Ошибка','Остановлено')]
            if not jobs: return
            for entry, _ in jobs:
                self.states[entry.href][2:]=[0,'Ожидает','']
                self.retry_attempts[entry.href]=0
            self.downloading=True
        self.stop.clear()
        self.paused=False
        self.sample=(time.monotonic(),self.received)
        self.rate_sample=self.sample
        if isinstance(self.screen, ErrorRetryScreen):
            self.screen.refresh_rows()
        self.retry_error_batch(jobs,self.batch_destination)

    @work(thread=True,group='downloads')
    def retry_error_batch(self,jobs,destination):
        try:
            with destination_lock(destination):
                for entry,target in jobs:
                    if not target.resolve().is_relative_to(destination.resolve()):
                        raise ValueError('Путь назначения выходит за выбранную папку')
                    self.download_one(entry,target,careful=True)
            successful_folders=[entry for entry in self.batch_picked if entry.directory and all(
                self.states[file.href][3]=='Готово'
                for file,_ in self.jobs if file.href.startswith(entry.href.rstrip('/')+'/'))]
            self.call_from_thread(self.clear_completed_folders,successful_folders)
        except Exception as exc:
            with self.lock:
                for entry,target in jobs:
                    if self.states[entry.href][3] != 'Ожидает': continue
                    self.states[entry.href][2:]=[0,'Ошибка',self.err(exc)]
                    self.error_messages[entry.href]=self.err(exc)
                    self.error_retryable[entry.href]=False
        finally:
            self.call_from_thread(self.finish_download)
    def clear_completed_folders(self, entries):
        table = self.query_one(DataTable)
        for entry in entries:
            if self.selected.get(entry.href) == entry:
                self.selected.pop(entry.href)
                if any(e.href == entry.href for e in self.entries):
                    table.update_cell(entry.href,next(iter(table.columns)),self.entry_cells(entry)[0])
        self.update_summary()
    def progress(self):
        if not self.query('#transfer-status'): return
        self.render_selection()
        with self.lock:
            if not self.states: return
            done=sum(v[0] for v in self.states.values()); total=sum(v[1] or 0 for v in self.states.values()); unknown=sum(v[1] is None for v in self.states.values()); now=time.monotonic()
            speed=(self.received-self.sample[1])/max(now-self.sample[0],.001); self.sample=(now,self.received)
            elapsed = now-self.rate_sample[0]
            if self.paused or not self.downloading:
                self.rate_sample = (now,self.received)
            elif elapsed >= 2:
                rate = (self.received-self.rate_sample[1])/elapsed
                if rate > 0: self.measured_speed = rate
                self.rate_sample = (now,self.received)
            complete=sum(v[3]=='Готово' for v in self.states.values()); errors=[f'{k}: {v[4]}' for k,v in self.states.items() if v[4]]
            pct=min(100,done/total*100) if total else (100 if complete == len(self.states) else 0)
            self.query_one('#bar',ProgressBar).update(progress=pct)
            self.query_one('#transfer').add_class('active')
            self.query_one('#pause-download',Button).label='Продолжить' if self.paused else 'Пауза'
            self.query_one('#pause-download',Button).disabled=not self.downloading
            self.query_one('#stop-download',Button).disabled=not self.downloading
            eta = f' · Осталось ≈ {duration(max(0,total-done)/self.measured_speed)}' if self.downloading and not self.paused and not unknown and not errors and speed > 0 and self.measured_speed > 0 and done < total else ''
            self.query_one('#transfer-status',Static).update(f'{"Пауза" if self.paused else "Загрузка" if self.downloading else "Остановлено" if self.stop.is_set() else "Завершено"}: {pct:.1f}% · {size(speed)}/s · {size(done)} / {size(total)}'+(f' (+{unknown} неизвестных размеров)' if unknown else '')+f'\nГотово: {complete}/{len(self.states)} · Ошибок: {len(errors)}'+eta+('\n'+errors[0] if errors else ''))
    async def action_quit(self):
        self.quitting=True
        self.stop.set(); self.paused=False
        if self.downloading:
            self.notify('Останавливаю потоки и сохраняю .part…',timeout=5)
            while self.downloading: await asyncio.sleep(.1)
        self.exit()

def main():
    if '--version' in sys.argv:
        print(__version__); return 0
    try: c=config()
    except (OSError, ValueError):
        print('Не удалось прочитать приватный файл доступа; проверьте владельца и права 0600.',file=sys.stderr); return 2
    dav = DAV(c['MAIL_CLOUD_USER'],c['MAIL_CLOUD_WEBDAV_KEY']) if c['MAIL_CLOUD_USER'] and c['MAIL_CLOUD_WEBDAV_KEY'] else None
    if PRIVATE_CREDENTIALS.exists() or PRIVATE_CREDENTIALS.is_symlink():
        c = {}; dav = None
    if '--check' in sys.argv:
        if dav is None: print('Нет сохранённых credentials; запустите TUI и заполните форму.',file=sys.stderr); return 2
        try: print('WebDAV объектов:',len(dav.list('/'))); return 0
        except Exception as e: print(f'WebDAV check failed: {e}',file=sys.stderr); return 1
    CloudApp(dav, c).run(); return 0
if __name__ == '__main__': raise SystemExit(main())
