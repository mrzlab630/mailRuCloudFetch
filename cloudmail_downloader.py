#!/usr/bin/env python3
"""Cloud.Mail.ru WebDAV TUI downloader."""
from __future__ import annotations
import asyncio, base64, json, os, re, stat, sys, tempfile, time, threading, webbrowser, xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import quote, unquote, urljoin, urlparse
import requests
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header, Input, Label, ProgressBar, Select, Static, DataTable, Button
from textual import work

BASE = "https://webdav.cloud.mail.ru/"
__version__ = "1.0.0"
PRIVATE_CREDENTIALS = Path.home() / '.config' / 'cloudmailru' / 'credentials.enc'
PROPFIND = b'''<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/><d:getcontentlength/><d:getlastmodified/><d:creationdate/><d:getcontenttype/><d:getetag/></d:prop></d:propfind>'''

def config():
    d = {}
    p = Path(__file__).with_name('.env')
    if p.exists():
        for line in p.read_text().splitlines():
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
    if PRIVATE_CREDENTIALS.parent.is_symlink() or not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.getuid():
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
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('Зашифрованный файл должен принадлежать вам и иметь права 0600')
    try:
        payload = json.loads(PRIVATE_CREDENTIALS.read_text(encoding='utf-8'))
        if payload.get('version') != 1: raise ValueError('Неподдерживаемая версия хранилища')
        salt = base64.b64decode(payload['salt']); nonce = base64.b64decode(payload['nonce']); ciphertext = base64.b64decode(payload['ciphertext'])
        raw = AESGCM(_derive(master, salt)).decrypt(nonce, ciphertext, b'cloudmailru-credentials-v1')
        data = json.loads(raw.decode('utf-8'))
        if not data.get('user') or not data.get('key'): raise ValueError('В хранилище нет полного набора credentials')
        return {'MAIL_CLOUD_USER': data['user'], 'MAIL_CLOUD_WEBDAV_KEY': data['key']}
    except (InvalidTag, KeyError, ValueError, json.JSONDecodeError, UnicodeError, base64.binascii.Error) as exc:
        raise ValueError('Не удалось расшифровать credentials: неверный мастер-пароль или повреждённый файл') from exc

def size(n):
    if n is None: return '—'
    x = float(n)
    for u in ('B','KiB','MiB','GiB','TiB'):
        if x < 1024 or u == 'TiB': return f'{x:.1f} {u}'
        x /= 1024

def clean(name): return re.sub(r'[\\/:*?"<>|\x00-\x1f]', '_', name) or 'unnamed'

@dataclass(frozen=True)
class Entry:
    href: str; name: str; directory: bool; bytes: int|None = None
    modified: str = ''; created: str = ''; content_type: str = ''; etag: str = ''

class DAV:
    def __init__(self, user, key):
        self.auth = (user, key); self.s = requests.Session(); self.s.auth = self.auth
        self.s.headers['User-Agent'] = 'cloud-mailru-tui/1.0'
    def url(self, href):
        path=urlparse(href).path
        if urlparse(href).netloc and urlparse(href).netloc != urlparse(BASE).netloc: raise ValueError('Посторонний сервер в WebDAV href')
        return BASE.rstrip('/') + quote(path, safe='/')
    def list(self, path='/'):
        r = self.s.request('PROPFIND', self.url(path), data=PROPFIND, headers={'Depth':'1','Content-Type':'application/xml'}, timeout=30,allow_redirects=False); r.raise_for_status()
        if r.status_code != 207: raise ValueError(f'PROPFIND HTTP {r.status_code}, ожидался 207')
        root, result = ET.fromstring(r.content), []
        for node in root.findall('{DAV:}response'):
            href = unquote(node.findtext('{DAV:}href','')); p = node.find('{DAV:}propstat/{DAV:}prop')
            if p is None or href.rstrip('/') == path.rstrip('/'): continue
            name = PurePosixPath(urlparse(href).path.rstrip('/')).name
            if name in ('.','..') or '\\' in name or '\x00' in name: raise ValueError('Небезопасное имя файла')
            if str(PurePosixPath(urlparse(href).path.rstrip('/')).parent) != path.rstrip('/') and not (path == '/' and str(PurePosixPath(urlparse(href).path.rstrip('/')).parent) == '/'): continue
            directory = p.find('{DAV:}resourcetype/{DAV:}collection') is not None
            raw = p.findtext('{DAV:}getcontentlength'); result.append(Entry(href,name,directory,int(raw) if raw and raw.isdigit() else None,p.findtext('{DAV:}getlastmodified',''),p.findtext('{DAV:}creationdate',''),p.findtext('{DAV:}getcontenttype',''),p.findtext('{DAV:}getetag','')))
        return sorted(result, key=lambda x:(not x.directory,x.name.casefold()))
    def get(self, entry, target, update, cancelled):
        if target.exists() or target.is_symlink(): raise ValueError('Файл уже существует; выберите другую папку назначения')
        target.parent.mkdir(parents=True, exist_ok=True); part = target.with_name(target.name+'.part'); meta=target.with_name(target.name+'.part.json')
        if part.is_symlink() or meta.is_symlink(): raise ValueError('Symlink вместо .part запрещён')
        identity={'path':entry.href,'size':entry.bytes,'etag':entry.etag,'modified':entry.modified}
        done=0
        if part.exists():
            if not meta.exists() or json.loads(meta.read_text()) != identity: raise ValueError('Частичный файл другой версии; переместите его перед повтором')
            done=part.stat().st_size
        elif meta.exists(): raise ValueError('Существующий .part.json не принадлежит этой загрузке')
        if part.exists() and entry.bytes is not None and done == entry.bytes:
            os.link(part,target); part.unlink(); meta.unlink(); update(done,done,0); return True
        if entry.bytes is not None and done > entry.bytes: raise ValueError('Частичный файл больше исходного')
        validator=entry.etag if entry.etag and not entry.etag.startswith('W/') else entry.modified
        headers={'Accept-Encoding':'identity'}
        if done and validator: headers.update({'Range':f'bytes={done}-','If-Range':validator})
        else: done=0
        # Per-transfer sessions avoid sharing mutable requests state across threads.
        with requests.get(self.url(entry.href),auth=self.auth,headers=headers,stream=True,timeout=(15,30),allow_redirects=False) as r:
            r.raise_for_status()
            if r.status_code == 200: done=0
            elif r.status_code == 206:
                match=re.fullmatch(r'bytes (\d+)-(\d+)/(\d+)',r.headers.get('Content-Range',''))
                if not match or int(match[1]) != done or int(match[2]) != int(match[3])-1: raise ValueError('Некорректный Content-Range')
            else: raise ValueError(f'GET HTTP {r.status_code}')
            if r.headers.get('Content-Encoding','identity') != 'identity': raise ValueError('Сжатый поток не поддерживает безопасное возобновление')
            total = int(r.headers['Content-Length'])+done if 'Content-Length' in r.headers else entry.bytes
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
        os.link(part,target); part.unlink(); meta.unlink(); return True

class CloudApp(App):
    CSS = 'Screen { background: #10151b; } DataTable { height: 1fr; } #bar { height: 3; } #hint { height: 3; color: $text-muted; } #settings, #credentials { height: 3; } #destination { width: 1fr; } #threads { width: 16; } #user, #key, #master { width: 1fr; } #details { height: 3; }'
    BINDINGS = [('q','quit','Выход'),('space','toggle','Выбрать'),('enter','open','Открыть'),('d','download','Скачать'),('b','back','Назад'),('o','browser','Браузер'),('r','refresh','Обновить'),('x','stop','Стоп'),('p','pause','Пауза')]
    def __init__(self, dav, credentials=None):
        super().__init__(); self.dav=dav; self.credentials=credentials or {}; self.path='/'; self.entries=[]; self.selected={}; self.dest=Path.cwd()/'downloads'; self.jobs=[]; self.total=0; self.done=0; self.speed=0
        self.states={}; self.lock=threading.RLock(); self.stop=threading.Event(); self.paused=False; self.downloading=False; self.received=0; self.sample=(time.monotonic(),0)
    def compose(self)->ComposeResult:
        yield Header()
        with Horizontal(id='settings'):
            yield Input(str(self.dest),placeholder='Папка назначения',id='destination')
            yield Select([(str(n)+' потоков',n) for n in (1,2,4,8,16)],value=4,allow_blank=False,id='threads')
            yield Button('Скачать',id='download')
        with Horizontal(id='credentials'):
            yield Input(self.credentials.get('MAIL_CLOUD_USER',''), placeholder='Логин Mail', password=True, id='user')
            yield Input(self.credentials.get('MAIL_CLOUD_WEBDAV_KEY',''), placeholder='WebDAV ключ', password=True, id='key')
            yield Input('', placeholder='Мастер-пароль (12+ символов)', password=True, id='master')
            yield Button('Сохранить зашифрованно',id='save-credentials')
            yield Button('Расшифровать',id='unlock-credentials')
        yield Static('',id='hint'); yield DataTable(cursor_type='row',id='table'); yield Static('',id='details'); yield ProgressBar(total=100,show_eta=False,id='bar'); yield Footer()
    def on_mount(self):
        self.title='MAIL CLOUD · WebDAV'; self.set_interval(.25,self.progress)
        if self.dav is not None: self.load()
        else: self.query_one('#hint',Static).update('Введите мастер-пароль и нажмите «Расшифровать» или заполните credentials и сохраните зашифрованно')
    def err(self,e):
        text = f'Ошибка: {e}'
        for value in self.credentials.values():
            if value: text = text.replace(value, '[скрыто]')
        return text[:200]
    @work(exclusive=True,group='load')
    async def load(self):
        if self.dav is None: return
        dav = self.dav
        try:
            entries=await asyncio.get_running_loop().run_in_executor(None,dav.list,self.path)
            if dav is self.dav: self.entries=entries; self.refresh_table()
        except Exception as e:
            if dav is self.dav: self.query_one('#hint',Static).update(self.err(e))
    def refresh_table(self):
        t=self.query_one(DataTable); t.clear(columns=True); t.add_columns(' ','Имя','Размер','Тип','Создано','Изменено')
        for e in self.entries: t.add_row('✓' if e.href in self.selected else ' ',e.name,'Папка' if e.directory else size(e.bytes), 'Папка' if e.directory else (e.content_type or Path(e.name).suffix or 'Файл'), e.created or '—',e.modified or '—',key=e.href)
        self.query_one('#hint',Static).update(f'{self.path}  |  выбрано: {len(self.selected)}  |  destination: {self.dest}')
    def action_toggle(self):
        if isinstance(self.focused,Input): return
        t=self.query_one(DataTable)
        if t.cursor_row is None or t.cursor_row >= len(self.entries): return
        e=self.entries[t.cursor_row]
        if e.href in self.selected: self.selected.pop(e.href)
        else: self.selected[e.href]=e
        t.update_cell(e.href,t.columns[next(iter(t.columns))].key,'✓' if e.href in self.selected else ' ')
        self.query_one('#hint',Static).update(f'{self.path} | Выбрано: {len(self.selected)}')
    def on_data_table_row_highlighted(self,event):
        if event.cursor_row < len(self.entries):
            e=self.entries[event.cursor_row]; self.query_one('#details',Static).update(f'{e.name}\nТип: {e.content_type or Path(e.name).suffix or "папка"} · Создано: {e.created or "не предоставлено WebDAV"}\nИзменено: {e.modified or "не предоставлено WebDAV"}')
    def action_open(self):
        if not self.entries: return
        e=self.entries[self.query_one(DataTable).cursor_row]
        if e.directory: self.path=e.href; self.load()
    def on_data_table_row_selected(self,event): self.action_open()
    def action_back(self): self.path=str(PurePosixPath(self.path.rstrip('/')).parent); self.path='/' if self.path=='.' else self.path; self.load()
    def action_refresh(self): self.load()
    def action_browser(self):
        path=self.entries[self.query_one(DataTable).cursor_row].href if self.entries else self.path
        webbrowser.open('https://cloud.mail.ru/home'+quote(path,safe='/')); self.query_one('#hint',Static).update('Открыт путь в веб-интерфейсе Mail Cloud; потребуется вход. Публичная ссылка WebDAV не предоставляется.')
    def action_stop(self): self.stop.set(); self.paused=False
    def action_pause(self): self.paused=not self.paused
    def on_button_pressed(self,event):
        if event.button.id == 'download': self.action_download()
        elif event.button.id == 'save-credentials': self.save_credentials()
        elif event.button.id == 'unlock-credentials': self.unlock_credentials()
    def unlock_credentials(self):
        if self.downloading:
            self.notify('Сначала остановите загрузку', severity='warning'); return
        master = self.query_one('#master', Input).value
        try:
            credentials = unlock_config(master)
            self.credentials = credentials
            self.dav = DAV(credentials['MAIL_CLOUD_USER'], credentials['MAIL_CLOUD_WEBDAV_KEY'])
            self.query_one('#user', Input).value = credentials['MAIL_CLOUD_USER']
            self.query_one('#key', Input).value = credentials['MAIL_CLOUD_WEBDAV_KEY']
            self.selected.clear(); self.entries=[]; self.states={}; self.path='/'; self.refresh_table(); self.load()
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
            self.credentials = {'MAIL_CLOUD_USER': user, 'MAIL_CLOUD_WEBDAV_KEY': key}
            self.dav = DAV(user, key)
            self.selected.clear(); self.entries=[]; self.states={}; self.path = '/'; self.refresh_table(); self.load()
            self.query_one('#hint', Static).update(f'Доступ сохранён зашифрованно: {PRIVATE_CREDENTIALS} (0600)')
        except (OSError, ValueError) as exc:
            self.query_one('#hint', Static).update(self.err(exc))
        finally:
            self.query_one('#master', Input).value = ''
    def action_download(self):
        if self.downloading or not self.selected: return
        self.dest=Path(self.query_one('#destination',Input).value).expanduser().absolute()
        self.downloading=True; self.stop.clear(); self.paused=False; self.states={}; self.received=0; self.sample=(time.monotonic(),0)
        self.download_batch(list(self.selected.values()),self.query_one('#threads',Select).value)
    @work(thread=True,group='downloads')
    def download_batch(self,picked,threads):
        try:
            self.call_from_thread(self.query_one('#hint',Static).update,'Рекурсивное сканирование выбранных папок…')
            jobs=[]; directories=[]; seen=set(); targets=set()
            roots=[e for e in picked if not any(p.directory and e.href.startswith(p.href.rstrip('/')+'/') for p in picked if p != e)]
            stack=[(e,self.dest/e.name) for e in roots]
            while stack:
                if self.stop.is_set(): return
                e,target=stack.pop()
                if e.href in seen: continue
                seen.add(e.href)
                if not target.resolve().is_relative_to(self.dest.resolve()): raise ValueError('Путь назначения выходит за выбранную папку')
                if target in targets: raise ValueError('Два объекта имеют одинаковый путь назначения')
                targets.add(target)
                if e.directory:
                    directories.append(target); stack.extend((c,target/c.name) for c in self.dav.list(e.href))
                else: jobs.append((e,target))
            self.total=sum(e.bytes or 0 for e,t in jobs)
            reserved=set()
            for e,t in jobs:
                for p in (t,t.with_name(t.name+'.part'),t.with_name(t.name+'.part.json')):
                    if p in reserved: raise ValueError('Имена файлов конфликтуют с .part; выберите файлы отдельно')
                    reserved.add(p)
            with self.lock: self.states={e.href:[0,e.bytes,0,'Ожидает',''] for e,t in jobs}
            for d in directories: d.mkdir(parents=True,exist_ok=True)
            with ThreadPoolExecutor(max_workers=threads) as pool:
                futures=[pool.submit(self.download_one,e,t) for e,t in jobs]
                for f in futures: f.result()
        except Exception as exc: self.call_from_thread(self.notify,self.err(exc),severity='error',timeout=15)
        finally: self.downloading=False
    def download_one(self,e,target):
        def cancelled():
            while self.paused and not self.stop.is_set(): time.sleep(.1)
            return self.stop.is_set()
        previous=[None]
        def up(done,total,speed):
            with self.lock:
                if previous[0] is not None: self.received+=done-previous[0]
                previous[0]=done; self.states[e.href]=[done,total,speed,'Скачивается','']
        try:
            if cancelled(): return
            ok=self.dav.get(e,target,up,cancelled)
            with self.lock: self.states[e.href][3]='Готово' if ok else 'Остановлено'; self.states[e.href][2]=0
        except Exception as ex:
            with self.lock: self.states[e.href][3]='Ошибка'; self.states[e.href][4]=self.err(ex); self.states[e.href][2]=0
    def progress(self):
        with self.lock:
            if not self.states: return
            done=sum(v[0] for v in self.states.values()); total=sum(v[1] or 0 for v in self.states.values()); unknown=sum(v[1] is None for v in self.states.values()); now=time.monotonic()
            speed=(self.received-self.sample[1])/max(now-self.sample[0],.001); self.sample=(now,self.received)
            complete=sum(v[3]=='Готово' for v in self.states.values()); errors=[f'{k}: {v[4]}' for k,v in self.states.items() if v[4]]
            pct=min(100,done/total*100) if total else (100 if complete == len(self.states) else 0)
            self.query_one('#bar',ProgressBar).update(progress=pct)
            self.query_one('#hint',Static).update(f'{"Пауза" if self.paused else "Загрузка" if self.downloading else "Завершено"}: {pct:.1f}% · {size(speed)}/s · {size(done)} / {size(total)}'+(f' (+{unknown} неизвестных размеров)' if unknown else '')+f'\nГотово: {complete}/{len(self.states)} · Ошибок: {len(errors)}'+('\n'+errors[0] if errors else ''))
    async def action_quit(self):
        self.stop.set(); self.paused=False
        if self.downloading:
            self.notify('Останавливаю потоки и сохраняю .part…',timeout=5)
            while self.downloading: await asyncio.sleep(.1)
        self.exit()

def main():
    try: c=config()
    except (OSError, ValueError):
        print('Не удалось прочитать приватный файл доступа; проверьте владельца и права 0600.',file=sys.stderr); return 2
    dav = DAV(c['MAIL_CLOUD_USER'],c['MAIL_CLOUD_WEBDAV_KEY']) if c['MAIL_CLOUD_USER'] and c['MAIL_CLOUD_WEBDAV_KEY'] else None
    if PRIVATE_CREDENTIALS.exists():
        c = {}; dav = None
    if '--check' in sys.argv:
        if dav is None: print('Нет сохранённых credentials; запустите TUI и заполните форму.',file=sys.stderr); return 2
        try: print('WebDAV объектов:',len(dav.list('/'))); return 0
        except Exception as e: print(f'WebDAV check failed: {e}',file=sys.stderr); return 1
    CloudApp(dav, c).run(); return 0
if __name__ == '__main__': raise SystemExit(main())
