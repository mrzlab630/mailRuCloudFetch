"""Durable download queue and read-only reconciliation with disk and WebDAV."""
from contextlib import contextmanager
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import sqlite3
import stat
import tempfile

JOURNAL_NAME = '.cloudmail-downloads.sqlite3'
RESERVED_NAMES = {'.cloudmail-download.lock', JOURNAL_NAME, JOURNAL_NAME + '-journal',
                  JOURNAL_NAME + '-wal', JOURNAL_NAME + '-shm'}


def source_id(base, dav):
    if dav is None:
        return None
    return hashlib.sha256((base + '\n' + getattr(dav, 'auth', ('', ''))[0]).encode()).hexdigest()


def saved_destination(path, source):
    if not path.exists():
        return None
    if path.is_symlink() or path.stat().st_size > 1024 * 1024:
        raise ValueError('Некорректный файл настроек загрузки')
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, dict) or data.get('version') != 1 or not isinstance(data.get('destinations'), dict):
        raise ValueError('Некорректные настройки папки загрузки')
    value = data.get('destinations', {}).get(source) if source else data.get('last')
    return Path(value) if isinstance(value, str) and Path(value).is_absolute() else None


def remember_destination(path, source, destination):
    data = {'version': 1, 'destinations': {}}
    if path.exists():
        saved_destination(path, source)
        data = json.loads(path.read_text(encoding='utf-8'))
    data.setdefault('destinations', {})[source] = str(destination)
    data['last'] = str(destination)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix='.session-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(data, stream, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def target_path(destination, relative):
    relative = PurePosixPath(relative)
    if relative.is_absolute() or not relative.parts or any(p in ('.', '..') or '\\' in p or '\x00' in p or ':' in p for p in relative.parts):
        raise ValueError('Небезопасный путь в журнале загрузки')
    target = destination.joinpath(*relative.parts)
    if not target.resolve().is_relative_to(destination.resolve()):
        raise ValueError('Путь загрузки выходит за папку назначения')
    current = target
    while current != destination:
        if current.is_symlink():
            raise ValueError('Symlink в пути загрузки')
        current = current.parent
    if any(p.casefold() in RESERVED_NAMES for p in relative.parts):
        raise ValueError('Имя совпадает со служебным файлом загрузки')
    return target


def signature(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('Вместо файла найден symlink или другой объект')
    return (info.st_size, info.st_mtime_ns)


def same_version(a, b):
    return all(a.get(key) == b.get(key) for key in ('href', 'bytes', 'etag', 'modified'))


class DownloadJournal:
    """Each write is an atomic SQLite transaction; callers hold destination_lock."""
    def __init__(self, destination, source):
        self.destination = destination.resolve()
        self.source = source
        self.path = self.destination / JOURNAL_NAME

    @contextmanager
    def connection(self, write=False):
        for suffix in ('', '-journal', '-wal', '-shm'):
            path = self.path.with_name(self.path.name + suffix)
            if path.is_symlink():
                raise ValueError('Symlink вместо журнала загрузки')
        if not write and not self.path.exists():
            yield None
            return
        # Existing journals need write access to roll back a hot SQLite journal after a crash.
        uri = self.path.as_uri() + ('?mode=rwc' if write else '?mode=rw')
        connection = sqlite3.connect(uri, uri=True, timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                if write:
                    connection.execute('''CREATE TABLE IF NOT EXISTS jobs (
                        source TEXT NOT NULL, target TEXT NOT NULL, entry TEXT NOT NULL,
                        status TEXT NOT NULL, local_size INTEGER, local_mtime INTEGER,
                        message TEXT NOT NULL DEFAULT '', PRIMARY KEY(source, target))''')
                yield connection
        finally:
            connection.close()

    def records(self):
        with self.connection() as connection:
            if connection is None:
                return {}
            result = {}
            for row in connection.execute('SELECT * FROM jobs WHERE source = ?', (self.source,)):
                record = dict(row)
                record['entry'] = json.loads(record['entry'])
                result[record['target']] = record
            return result

    def register(self, jobs):
        previous = self.records()
        rows = []
        for entry, target in jobs:
            relative = target.relative_to(self.destination).as_posix()
            target_path(self.destination, relative)
            data = asdict(entry)
            old = previous.get(relative, {})
            if not same_version(data, old.get('entry', {})): old = {}
            rows.append((self.source, relative, json.dumps(data, sort_keys=True), old.get('status', 'queued'),
                         old.get('local_size'), old.get('local_mtime'), old.get('message', '')))
        with self.connection(write=True) as connection:
            connection.executemany('''INSERT INTO jobs(source, target, entry, status, local_size, local_mtime, message)
                VALUES(?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source, target) DO UPDATE SET
                status=excluded.status, local_size=excluded.local_size, local_mtime=excluded.local_mtime,
                message=excluded.message, entry=excluded.entry''', rows)

    def update(self, target, status, message='', published=None):
        relative = target.relative_to(self.destination).as_posix()
        target_path(self.destination, relative)
        local = signature(published) if published is not None else None
        with self.connection(write=True) as connection:
            connection.execute('''UPDATE jobs SET status=?, message=?, local_size=?, local_mtime=?
                WHERE source=? AND target=?''',
                (status, message, local[0] if local else None, local[1] if local else None, self.source, relative))


def inspect_destination(destination, source, visible, list_remote, cancelled=lambda: False, visible_only=False):
    """Return a snapshot only. Never adopt, delete, rename, or download local data."""
    if not destination.is_dir():
        return {}
    journal = DownloadJournal(destination, source)
    records = journal.records()
    if visible_only:
        hrefs = {entry.href for entry in visible if not entry.directory}
        records = {key: record for key, record in records.items()
                   if record['entry'] and record['entry']['href'] in hrefs}
    # Import older partials by their account-bound metadata, without modifying them.
    for directory, names, files in (() if visible_only else os.walk(destination, followlinks=False)):
        if cancelled():
            return {}
        names[:] = [name for name in names if not (Path(directory) / name).is_symlink()]
        for name in files:
            if not name.endswith(('.part', '.part.json')):
                continue
            target = Path(directory) / name[:(-10 if name.endswith('.part.json') else -5)]
            relative = target.relative_to(destination).as_posix()
            if relative in records:
                continue
            meta = target.with_name(target.name + '.part.json')
            try:
                target_path(destination, relative)
                if signature(meta) is None or meta.stat().st_size > 65536:
                    raise ValueError('Нет корректных сведений для продолжения .part')
                data = json.loads(meta.read_text(encoding='utf-8'))
                if not isinstance(data, dict): raise ValueError('Некорректный .part.json')
                if data.get('source') != source:
                    continue
                href = data['path']
                if not isinstance(href, str) or not href.startswith('/') or href.startswith('//') or '..' in PurePosixPath(href).parts:
                    raise ValueError('Некорректный путь облака в .part.json')
                entry = dict(href=href, name=PurePosixPath(href).name, directory=False,
                             bytes=data['size'], etag=data['etag'], modified=data['modified'], created='', content_type='')
                records[relative] = dict(target=relative, entry=entry, status='queued', local_size=None, local_mtime=None, message='')
            except (OSError, ValueError, KeyError, TypeError) as exc:
                records[relative] = dict(target=relative, entry=None, status='attention', message=str(exc))

    # Old completed files have no provenance: offer explicit adoption, never silently skip them.
    known_hrefs = {record['entry']['href'] for record in records.values() if record['entry']}
    for entry in visible:
        if cancelled():
            return {}
        if entry.directory or entry.href in known_hrefs:
            continue
        parts = PurePosixPath(entry.href).parts[1:]
        for start in range(len(parts)):
            relative = PurePosixPath(*parts[start:]).as_posix()
            if relative in records:
                continue
            try:
                target = target_path(destination, relative)
                if signature(target) is not None:
                    records[relative] = dict(target=relative, entry=asdict(entry), status='found',
                                             local_size=None, local_mtime=None, message='')
                elif visible_only and any(target.with_name(target.name + suffix).exists()
                                          or target.with_name(target.name + suffix).is_symlink()
                                          for suffix in ('.part', '.part.json')):
                    records[relative] = dict(target=relative, entry=asdict(entry), status='queued',
                                             local_size=None, local_mtime=None, message='')
            except (OSError, ValueError):
                continue

    listings = {}
    result = {}
    for relative, record in records.items():
        if cancelled():
            return {}
        entry = record['entry']
        item = dict(record, done=0, total=entry.get('bytes') if entry else None,
                    can_resume=False, can_accept=False)
        result[relative] = item
        try:
            target = target_path(destination, relative)
            if entry is None:
                item['status'] = 'attention'
                continue
            parent = str(PurePosixPath(entry['href']).parent)
            if parent not in listings:
                try:
                    listings[parent] = {e.href: asdict(e) for e in list_remote(parent)}
                except Exception as exc:
                    listings[parent] = exc
            listing = listings[parent]
            if isinstance(listing, Exception):
                raise ValueError('Не удалось проверить папку в облаке; нажмите «Проверить»')
            remote = listing.get(entry['href'])
            if remote is None or remote.get('directory') or not same_version(entry, remote):
                raise ValueError('Файл удалён или изменился в облаке; требуется проверка')
            item['entry'] = remote
            local = signature(target)
            if local is not None:
                item['done'] = local[0]
                if local[0] != remote['bytes']:
                    raise ValueError('Размер файла на диске отличается от облака')
                recorded = (record.get('local_size'), record.get('local_mtime'))
                if record['status'] in ('complete', 'publishing') and local == recorded:
                    if not (remote.get('etag') or remote.get('modified')):
                        raise ValueError('Облако не сообщает версию файла; требуется проверка')
                    item.update(status='complete', message='Скачан')
                elif record['status'] == 'found' or recorded == (None, None):
                    item.update(status='found', can_accept=True,
                                message='Найден на диске. Путь и размер совпадают; содержимое не проверено. «Принять файл» подтверждает этот экземпляр.')
                else:
                    raise ValueError('Локальный файл изменился или его публикация не подтверждена')
                continue
            partial = target.with_name(target.name + '.part')
            meta = target.with_name(target.name + '.part.json')
            saved = signature(partial)
            if saved is not None:
                metadata = signature(meta)
                if metadata is None or metadata[0] > 65536:
                    raise ValueError('Нет корректных сведений для продолжения .part')
                data = json.loads(meta.read_text(encoding='utf-8'))
                expected = dict(path=entry['href'], size=entry['bytes'], etag=entry['etag'],
                                modified=entry['modified'], source=source)
                if data != expected or (entry['bytes'] is not None and saved[0] > entry['bytes']):
                    raise ValueError('Частичный файл не соответствует аккаунту или версии облака')
                failed = record['status'] == 'error'
                item.update(status='error' if failed else 'partial', done=saved[0], can_resume=True,
                            message=record['message'] if failed else 'Можно продолжить')
            elif signature(meta) is not None:
                raise ValueError('Найдены метаданные без .part; требуется проверка')
            else:
                item.update(status='error' if record['status'] == 'error' else 'queued', can_resume=True)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            item.update(status='attention', message=str(exc))
    return result


def inspect_folders(destination, visible, files, list_remote, cancelled=lambda: False):
    """Check mapped trees and return folder states plus incomplete nested files.

    Folder keys are remote hrefs; file keys are local relative paths so the
    caller can merge them into the durable recovery queue.
    """
    result = {}
    priority = {'complete': 0, 'found': 1, 'queued': 2, 'partial': 2, 'error': 3, 'attention': 4}
    for root in visible:
        if cancelled(): return {}
        if not root.directory: continue
        candidates, unsafe = [], False
        parts = PurePosixPath(root.href).parts[1:]
        for start in range(len(parts)):
            relative = PurePosixPath(*parts[start:])
            try:
                target = target_path(destination, relative)
                if target.is_dir(): candidates.append(relative)
                elif target.exists(): unsafe = True
            except (OSError, ValueError):
                unsafe = True
        if not candidates and not unsafe: continue
        item = dict(entry=asdict(root), status='attention', message='Не удалось однозначно сопоставить папку на диске')
        result[root.href] = item
        if len(candidates) != 1: continue
        stack = [(root, candidates[0], item, None)]
        while stack:
            if cancelled(): return {}
            entry, relative, item, children = stack.pop()
            if children is not None:
                status = max((child['status'] for child in children), key=priority.get, default='complete')
                item['status'] = 'partial' if status == 'queued' else status
                item['message'] = ''
                continue
            try:
                target = target_path(destination, relative)
                if not target.is_dir():
                    item.update(status='partial', message='Подпапка отсутствует на диске')
                    continue
                entries = list_remote(entry.href)
                children = []
                descendants = []
                for child in entries:
                    if cancelled(): return {}
                    if PurePosixPath(child.href).parent != PurePosixPath(entry.href) or child.name != PurePosixPath(child.href).name:
                        raise ValueError('Некорректный путь вложенного объекта в облаке')
                    child_relative = relative / child.name
                    child_item = dict(entry=asdict(child), status='attention', message='')
                    children.append(child_item)
                    if child.directory:
                        result[child.href] = child_item
                        descendants.append((child, child_relative, child_item, None))
                        continue
                    try:
                        local = signature(target_path(destination, child_relative))
                        record = files.get(child_relative.as_posix(), {})
                        if record and (not record.get('entry') or not same_version(record['entry'], asdict(child))):
                            status = 'attention'
                        elif record.get('status') in ('attention', 'error'):
                            status = record['status']
                        elif local is None and record.get('status') in ('partial', 'queued', 'stopped'):
                            status = record['status']
                        elif local is None:
                            status = 'queued'
                        elif child.bytes is None or local[0] != child.bytes:
                            status = 'partial' if child.bytes is not None and local[0] < child.bytes else 'attention'
                        elif record.get('status') == 'complete':
                            status = 'complete' if local == (record.get('local_size'), record.get('local_mtime')) else 'attention'
                        else:
                            status = 'found'
                        child_item['status'] = status
                        if not child.directory and status not in ('complete', 'found'):
                            child_item.update(
                                target=child_relative.as_posix(),
                                done=local[0] if local is not None else record.get('done', 0),
                                total=child.bytes,
                                can_resume=status in ('queued', 'partial', 'error', 'stopped'),
                                can_accept=False,
                                retryable=False,
                                message=(record.get('message', '') if status in ('error', 'attention') else
                                         'Ожидает скачивания' if status == 'queued' else
                                         'Можно продолжить' if status == 'partial' else ''))
                            result[child_relative.as_posix()] = child_item
                    except (OSError, ValueError):
                        child_item['status'] = 'attention'
                stack.append((entry, relative, item, children))
                stack.extend(descendants)
            except Exception:
                item.update(status='attention', message='Не удалось проверить содержимое папки')
    return result
