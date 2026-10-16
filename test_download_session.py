import asyncio
from collections import Counter
from dataclasses import asdict
import json
from pathlib import Path
import threading

import pytest

import cloudmail_downloader as m
from download_state import DownloadJournal, JOURNAL_NAME, inspect_destination, signature, source_id
from test_downloader import DATA, Handler, http_server
from test_download_recovery import wait_for_batch


async def wait_for_scan(app, pilot):
    for _ in range(120):
        await pilot.pause(.05)
        if not app.recovery_scanning:
            assert not app.recovery_error, app.recovery_error
            return
    raise AssertionError('Destination scan did not finish')


def metadata(entry, source):
    return dict(path=entry.href, size=entry.bytes, etag=entry.etag, modified=entry.modified, source=source)


@pytest.mark.parametrize('terminal_size', [(80, 24), (120, 35)])
def test_resume_shows_live_transfer_progress_and_controls(tmp_path, terminal_size):
    entry = m.Entry('/file', 'file', False, 8, etag='"v1"')
    started, advance, advanced, finish = (threading.Event() for _ in range(4))
    target = tmp_path / 'file'
    partial = tmp_path / 'file.part'
    meta = tmp_path / 'file.part.json'

    class Fake:
        auth = ('progress-account', 'key')
        def list(self, path): return [entry]
        def get(self, entry, target, update, cancelled, read_timeout=30):
            update(2, 8, 0)
            started.set()
            for _ in range(500):
                if advance.wait(.01): break
                if cancelled(): return False
            else: raise AssertionError('test did not release first download stage')
            partial.write_bytes(b'abcdef')
            update(6, 8, 4)
            advanced.set()
            for _ in range(500):
                if finish.wait(.01): break
                if cancelled(): return False
            else: raise AssertionError('test did not release final download stage')
            target.write_bytes(b'abcdefgh')
            partial.unlink(); meta.unlink()
            update(8, 8, 4)
            return True

    async def check():
        app = m.CloudApp(Fake())
        partial.write_bytes(b'ab')
        meta.write_text(json.dumps(metadata(entry, source_id(m.BASE, app.dav))))
        watchdog = threading.Timer(8, app.stop.set)
        watchdog.daemon = True
        watchdog.start()
        async with app.run_test(size=terminal_size) as pilot:
            app.query_one('#destination', m.Input).value = str(tmp_path)
            await wait_for_scan(app, pilot)
            app.action_show_resume()
            await pilot.pause(.1)
            screen = app.screen
            assert not screen.query_one('#resume-transfer').display
            await pilot.click('#resume-all')
            assert await asyncio.to_thread(started.wait, 2)
            await pilot.pause(.1)
            assert screen.query_one('#resume-transfer').display
            bar = screen.query_one('#resume-bar', m.ProgressBar)
            assert bar.progress == 25
            text = str(screen.query_one('#resume-transfer-status', m.Static).render())
            assert 'Загрузка: 25.0%' in text
            assert '2.0 B / 8.0 B' in text
            assert text == str(app.query_one('#transfer-status', m.Static).render())
            for selector in ('#resume-bar', '#resume-pause', '#resume-stop', '#resume-all', '#resume-close'):
                assert screen.query_one('#resume-dialog').content_region.contains_region(screen.query_one(selector).region)
            advance.set()
            assert await asyncio.to_thread(advanced.wait, 2)
            await pilot.pause(.3)
            assert bar.progress == 75
            text = str(screen.query_one('#resume-transfer-status', m.Static).render())
            assert '6.0 B / 8.0 B' in text and '/s' in text
            assert 'Готово: 0/1 · Ошибок: 0' in text
            await pilot.click('#resume-pause')
            assert app.paused
            assert 'Пауза: 75.0%' in str(screen.query_one('#resume-transfer-status', m.Static).render())
            assert str(screen.query_one('#resume-pause', m.Button).label) == 'Продолжить'
            await pilot.pause(.3)
            await pilot.click('#resume-pause')
            assert not app.paused
            await pilot.click('#resume-stop')
            await wait_for_batch(app, pilot)
            app.progress()
            assert 'Остановлено:' in str(screen.query_one('#resume-transfer-status', m.Static).render())
            assert screen.query_one('#resume-pause', m.Button).disabled
            await wait_for_scan(app, pilot)
            await pilot.click('#resume-all')
            finish.set()
            await wait_for_batch(app, pilot)
            await wait_for_scan(app, pilot)
            app.progress()
            assert bar.progress == 100
            assert 'Завершено: 100.0%' in str(screen.query_one('#resume-transfer-status', m.Static).render())
            assert 'Готово: 1/1' in str(screen.query_one('#resume-transfer-status', m.Static).render())
            await pilot.press('escape')
            app.action_show_resume()
            await pilot.pause(.1)
            assert app.screen.query_one('#resume-bar', m.ProgressBar).progress == 100
            assert target.read_bytes() == b'abcdefgh'
        watchdog.cancel()
    try:
        asyncio.run(check())
    finally:
        advance.set(); finish.set()


def test_restart_restores_completed_partial_and_unstarted_queue(tmp_path):
    folder = m.Entry('/archive', 'archive', True)
    entries = [m.Entry('/archive/' + name, name, False, len(DATA), etag='"v1"')
               for name in ('waiting', 'partial', 'complete')]
    calls = Counter()
    ranges = []

    class Server(Handler):
        def do_GET(self):
            name = self.path.rsplit('/', 1)[-1]
            calls[name] += 1
            ranges.append((name, self.headers.get('Range')))
            super().do_GET()

    with http_server(Server):
        dav = m.DAV('account', 'test-key')
        dav.list = lambda path: [folder] if path == '/' else entries
        original = dav.get
        stop_during_partial = True

        def get(entry, target, update, cancelled, **kwargs):
            def progress(done, total, rate):
                update(done, total, rate)
                if stop_during_partial and entry.name == 'partial' and done >= 256 * 1024:
                    app.stop.set()
            return original(entry, target, progress, cancelled, **kwargs)
        dav.get = get

        async def check():
            nonlocal app, stop_during_partial
            app = m.CloudApp(dav)
            async with app.run_test(size=(80, 24)) as pilot:
                await pilot.pause(.15)
                app.query_one('#destination', m.Input).value = str(tmp_path)
                app.query_one('#threads', m.Select).value = 1
                app.selected = {folder.href: folder}
                app.action_download()
                await wait_for_batch(app, pilot)
                assert app.states[entries[2].href][3] == 'Готово'
                assert app.states[entries[1].href][3] == 'Остановлено'
                assert app.states[entries[0].href][3] == 'Остановлено'
                assert not app.error_jobs
                assert (tmp_path / 'archive/complete').read_bytes() == DATA
                assert (tmp_path / 'archive/partial.part').stat().st_size == 256 * 1024
                assert not (tmp_path / 'archive/waiting').exists()
                await app.action_quit()

            stop_during_partial = False
            app = m.CloudApp(dav)
            assert app.dest == tmp_path
            async with app.run_test(size=(80, 24)) as pilot:
                await wait_for_scan(app, pilot)
                assert calls == Counter(complete=1, partial=1)
                assert app.recovery['archive/complete']['status'] == 'complete'
                assert app.recovery['archive/partial']['status'] == 'partial'
                assert app.recovery['archive/waiting']['status'] == 'queued'
                app.action_open()
                await pilot.pause(.1)
                await wait_for_scan(app, pilot)
                table = app.query_one('#table', m.DataTable)
                assert table.get_row('/archive/complete')[1].style == '#7f8793'
                assert table.get_row('/archive/partial')[1].style == '#e5c07b'
                app.action_show_resume()
                await pilot.pause(.1)
                screen = app.screen
                assert isinstance(screen, m.ResumeScreen)
                assert screen.order == ['archive/partial', 'archive/waiting']
                for selector in ('#resume-all', '#resume-selected', '#resume-refresh', '#resume-accept', '#resume-close'):
                    assert screen.query_one('#resume-dialog').region.contains_region(screen.query_one(selector).region)
                # Resume only one file; preserve the other queued item across closing/reopening.
                await pilot.click('#resume-table', offset=(5, 1))
                assert screen.checked == {'archive/partial'}
                await pilot.click('#resume-selected')
                await wait_for_batch(app, pilot)
                await wait_for_scan(app, pilot)
                assert screen.order == ['archive/waiting']
                assert not screen.checked
                assert ('partial', 'bytes=262144-') in ranges
                assert (tmp_path / 'archive/partial').read_bytes() == DATA
                await pilot.click('#resume-all')
                await wait_for_batch(app, pilot)
                await wait_for_scan(app, pilot)
                assert screen.order == []
                assert screen.query_one('#resume-all', m.Button).disabled
                assert calls == Counter(complete=1, partial=2, waiting=1)
                assert (tmp_path / 'archive/waiting').read_bytes() == DATA
                await pilot.press('escape')
                # Selecting the entire folder again must skip all confirmed files.
                app.selected = {folder.href: folder}
                app.action_download()
                await wait_for_batch(app, pilot)
                assert calls == Counter(complete=1, partial=2, waiting=1)
                assert all(state[3] == 'Готово' for state in app.states.values())
                assert not app.error_jobs
                await wait_for_scan(app, pilot)
                # A later scan must not reapply an old in-memory completion after deletion.
                (tmp_path / 'archive/complete').unlink()
                app.schedule_recovery_scan()
                await wait_for_scan(app, pilot)
                app.render_recovery()
                assert app.recovery['archive/complete']['status'] == 'queued'
                assert '/archive/complete' not in app.downloaded
        app = None
        asyncio.run(check())


@pytest.mark.parametrize('dialog', ['errors', 'resume'])
def test_common_dialog_removes_successes_and_focuses_real_failures(tmp_path, dialog):
    entries = [m.Entry('/' + name, name, False, 4, etag='"v1"') for name in ('good', 'bad', 'slow')]
    found = m.Entry('/existing', 'existing', False, 4, etag='"v1"')
    started, release = threading.Event(), threading.Event()
    calls = Counter()
    repaired = False

    class Fake:
        auth = ('mixed-account', 'key')
        def list(self, path): return entries + [found]
        def get(self, entry, target, update, cancelled, read_timeout=30):
            calls[entry.name] += 1
            if dialog == 'errors' and calls[entry.name] == 1:
                raise m.requests.ReadTimeout('initial failure')
            if entry.name == 'bad' and not repaired: raise ValueError('Некорректный Content-Range')
            if entry.name == 'slow':
                update(1, 4, 0)
                started.set()
                assert release.wait(5)
            target.write_bytes(b'done')
            for suffix in ('.part', '.part.json'):
                target.with_name(target.name + suffix).unlink(missing_ok=True)
            update(4, 4, 0)
            return True

    async def check():
        nonlocal repaired
        app = m.CloudApp(Fake())
        if dialog == 'resume':
            (tmp_path / found.name).write_bytes(b'old!')
            for entry in entries:
                (tmp_path / (entry.name + '.part')).write_bytes(b'd')
                (tmp_path / (entry.name + '.part.json')).write_text(json.dumps(metadata(entry, source_id(m.BASE, app.dav))))
        async with app.run_test(size=(80, 24)) as pilot:
            app.query_one('#destination', m.Input).value = str(tmp_path)
            await wait_for_scan(app, pilot)
            if dialog == 'resume':
                app.action_show_resume()
                await pilot.pause(.1)
                screen = app.screen
                assert screen.order == ['bad', 'good', 'slow']
                assert str(app.query_one('#show-resume', m.Button).label) == 'Докачка (3)'
                assert 'Незавершённых: 3 · можно продолжить: 3' in str(screen.widget('summary', m.Static).render())
                screen.widget('filter', m.Select).value = 'attention'
                await pilot.pause(.05)
                assert screen.order == ['existing']
                screen.widget('table', m.DataTable).move_cursor(row=screen.order.index('existing'))
                await pilot.pause(.05)
                assert 'Найден на диске' in str(screen.widget('details', m.Static).render())
                screen.widget('filter', m.Select).value = 'all'
                await pilot.pause(.05)
                app.start_resume(['good', 'bad', 'slow'])
            else:
                app.selected = {entry.href: entry for entry in entries}
                app.action_download()
                await wait_for_batch(app, pilot)
                screen = app.screen
                app.start_error_retry(['/good', '/bad', '/slow'])
            assert isinstance(screen, m.DownloadTasksScreen)
            assert await asyncio.to_thread(started.wait, 2)
            await pilot.pause(.1)
            prefix = screen.prefix
            good_key = 'good' if dialog == 'resume' else '/good'
            slow_key = 'slow' if dialog == 'resume' else '/slow'
            bad_key = 'bad' if dialog == 'resume' else '/bad'
            assert good_key not in screen.order
            assert slow_key in screen.order
            assert app.downloading
            assert screen.query_one(m.DownloadProgress).display
            for selector in (f'#{prefix}-bar', '#resume-stop' if dialog == 'resume' else '#retry-stop'):
                assert screen.widget('dialog', m.Vertical).content_region.contains_region(screen.query_one(selector).region)
            release.set()
            await wait_for_batch(app, pilot)
            await wait_for_scan(app, pilot)
            assert app.screen is screen
            assert not app.downloading
            assert good_key not in screen.order and slow_key not in screen.order
            assert screen.current_key() == bad_key
            assert 'Некорректный Content-Range' in str(screen.widget('details', m.Static).render())
            assert 'Завершено с ошибками:' in str(screen.widget('transfer-status', m.Static).render())
            assert 'Готово: 2/3 · Ошибок: 1' in str(screen.widget('transfer-status', m.Static).render())
            screen.widget('filter', m.Select).value = 'errors'
            await pilot.pause(.1)
            assert screen.order == [bad_key]
            repaired = True
            if dialog == 'resume':
                assert app.recovery['bad']['status'] == 'error'
                screen.widget('table', m.DataTable).focus()
                await pilot.press('space')
                await pilot.click('#resume-selected')
            else:
                await pilot.click('#retry-current')
            await wait_for_batch(app, pilot)
            await wait_for_scan(app, pilot)
            assert screen.order == []
            assert (tmp_path / 'bad').read_bytes() == b'done'
            assert 'Ошибок: 0' in str(screen.widget('transfer-status', m.Static).render())
            assert not screen.widget('transfer-status', m.Static).render().plain.startswith('Завершено с ошибками')
    try:
        asyncio.run(check())
    finally:
        release.set()


def test_journal_checks_local_changes_cloud_versions_and_account(tmp_path):
    entry = m.Entry('/folder/file', 'file', False, 4, etag='"v1"')
    target = tmp_path / 'file'
    source = 'account-one'
    journal = DownloadJournal(tmp_path, source)
    journal.register([(entry, target)])
    target.write_bytes(b'done')
    journal.update(target, 'complete', published=target)
    listing = lambda path: [entry]
    scan = lambda: inspect_destination(tmp_path, source, [], listing)
    assert scan()['file']['status'] == 'complete'
    assert not inspect_destination(tmp_path, 'other-account', [], listing)
    target.unlink()
    assert scan()['file']['status'] == 'queued'
    assert scan()['file']['can_resume']
    target.write_bytes(b'nope')
    assert scan()['file']['status'] == 'attention'
    journal.update(target, 'complete', published=target)
    changed = m.Entry('/folder/file', 'file', False, 4, etag='"v2"')
    assert inspect_destination(tmp_path, source, [], lambda path: [changed])['file']['status'] == 'attention'
    assert inspect_destination(tmp_path, source, [], lambda path: [])['file']['status'] == 'attention'
    assert target.read_bytes() == b'nope'


def test_journal_recovers_crash_during_publication(tmp_path):
    entry = m.Entry('/file', 'file', False, 4, etag='"v1"')
    journal = DownloadJournal(tmp_path, 'source')
    target, part = tmp_path / 'file', tmp_path / 'file.part'
    journal.register([(entry, target)])
    part.write_bytes(b'done')
    journal.update(target, 'publishing', published=part)
    m.publish_partial(part, target)
    # Process died after publication and before recording the final completion.
    snapshot = inspect_destination(tmp_path, 'source', [], lambda path: [entry])
    assert snapshot['file']['status'] == 'complete'
    assert target.read_bytes() == b'done'


def test_imports_legacy_partials_without_mutating_or_trusting_other_accounts(tmp_path):
    entry = m.Entry('/nested/file', 'file', False, 10, etag='"v1"')
    source = 'source'
    part, meta = tmp_path / 'file.part', tmp_path / 'file.part.json'
    part.write_bytes(b'abc')
    meta.write_text(json.dumps(metadata(entry, source)))
    original = meta.read_bytes()
    snapshot = inspect_destination(tmp_path, source, [], lambda path: [entry])
    assert snapshot['file']['status'] == 'partial'
    assert snapshot['file']['done'] == 3
    assert snapshot['file']['can_resume']
    assert not inspect_destination(tmp_path, 'other-account', [], lambda path: [entry])
    assert not (tmp_path / JOURNAL_NAME).exists()
    assert meta.read_bytes() == original and part.read_bytes() == b'abc'
    meta.write_text('{broken')
    snapshot = inspect_destination(tmp_path, source, [], lambda path: [entry])
    assert snapshot['file']['status'] == 'attention'
    assert not snapshot['file']['can_resume']


def test_old_completed_file_requires_explicit_adoption(tmp_path):
    entry = m.Entry('/file', 'file', False, 4, etag='"v1"')
    (tmp_path / 'file').write_bytes(b'done')
    class Fake:
        auth = ('legacy-account', 'key')
        def list(self, path): return [entry]
    async def check():
        app = m.CloudApp(Fake())
        async with app.run_test(size=(80, 24)) as pilot:
            app.query_one('#destination', m.Input).value = str(tmp_path)
            await wait_for_scan(app, pilot)
            assert app.recovery['file']['status'] == 'found'
            assert not app.downloaded
            assert not (tmp_path / JOURNAL_NAME).exists()
            assert str(app.query_one('#show-resume', m.Button).label) == 'Докачка'
            assert not app.query_one('#resume-info', m.Static).display
            app.action_show_resume()
            await pilot.pause(.1)
            assert app.screen.order == []
            assert 'Незавершённых: 0 · можно продолжить: 0' in str(app.screen.widget('summary', m.Static).render())
            assert app.screen.query_one('#resume-accept', m.Button).disabled
            assert app.screen.query_one('#resume-all', m.Button).disabled
            app.start_resume(['file'])
            assert not app.downloading
            assert not (tmp_path / JOURNAL_NAME).exists()
            app.screen.widget('filter', m.Select).value = 'attention'
            await pilot.pause(.05)
            assert app.screen.order == ['file']
            assert not app.screen.query_one('#resume-accept', m.Button).disabled
            await pilot.click('#resume-accept')
            await pilot.pause(.1)
            await wait_for_scan(app, pilot)
            assert app.recovery['file']['status'] == 'complete'
            assert app.downloaded[entry.href] == entry
            app.screen.widget('filter', m.Select).value = 'all'
            await pilot.pause(.05)
            assert not app.screen.order
            assert (tmp_path / 'file').read_bytes() == b'done'
    asyncio.run(check())


@pytest.mark.parametrize('relative', ['../escape', '/absolute', 'C:/escape', '.cloudmail-downloads.sqlite3'])
def test_journal_rejects_external_or_reserved_targets(tmp_path, relative):
    from download_state import target_path
    with pytest.raises(ValueError): target_path(tmp_path, relative)


def test_folder_completion_is_recursive_and_rechecked_after_restart(tmp_path):
    folder = m.Entry('/archive', 'archive', True)
    nested = m.Entry('/archive/nested', 'nested', True)
    empty = m.Entry('/archive/empty', 'empty', True)
    file = m.Entry('/archive/nested/file', 'file', False, 4, etag='"v1"')
    calls = Counter()
    tree = {'/': [folder], folder.href: [nested, empty], nested.href: [file], empty.href: []}
    class Fake:
        auth = ('folders-account', 'key')
        def list(self, path):
            calls[path] += 1
            return tree[path]
    target = tmp_path / 'archive/nested/file'
    target.parent.mkdir(parents=True)
    (tmp_path / 'archive/empty').mkdir()
    target.write_bytes(b'done')
    journal = DownloadJournal(tmp_path, source_id(m.BASE, Fake()))
    journal.register([(file, target)])
    journal.update(target, 'complete', published=target)

    async def check():
        for restart in range(2):
            app = m.CloudApp(Fake())
            async with app.run_test(size=(80, 24)) as pilot:
                app.query_one('#destination', m.Input).value = str(tmp_path)
                await wait_for_scan(app, pilot)
                table = app.query_one('#table', m.DataTable)
                row = table.get_row(folder.href)
                assert row[1].style == '#7f8793'
                assert row[-1].plain == 'Скачана'
                assert set(app.recovery) == {'archive/nested/file'}
                assert str(app.query_one('#show-resume', m.Button).label) == 'Докачка'
                app.action_open()
                await pilot.pause(.1)
                await wait_for_scan(app, pilot)
                for entry in (nested, empty):
                    assert table.get_row(entry.href)[1].style == '#7f8793'
                assert calls['/archive'] == restart + 1
                assert calls['/archive/nested'] == restart + 1
                assert calls['/archive/empty'] == restart + 1
                if restart:
                    app.action_back()
                    await pilot.pause(.1)
                    await wait_for_scan(app, pilot)
                    target.unlink()
                    app.schedule_recovery_scan()
                    await wait_for_scan(app, pilot)
                    row = table.get_row(folder.href)
                    assert row[1].style == '#e5c07b'
                    assert row[-1].plain == 'Частично'
                    assert app.recovery['archive/nested/file']['can_resume']
    asyncio.run(check())


@pytest.mark.parametrize('relative', ['remote/album', 'album'])
def test_folder_scan_recognizes_legacy_nested_files_without_adoption(tmp_path, relative):
    folder = m.Entry('/remote/album', 'album', True)
    nested = m.Entry('/remote/album/nested', 'nested', True)
    file = m.Entry('/remote/album/nested/file', 'file', False, 4, etag='"v1"')
    target = tmp_path / relative / 'nested/file'
    target.parent.mkdir(parents=True)
    target.write_bytes(b'done')
    tree = {folder.href: [nested], nested.href: [file]}
    folders = m.inspect_folders(tmp_path, [folder], {}, tree.__getitem__)
    assert folders[folder.href]['status'] == 'found'
    assert folders[nested.href]['status'] == 'found'
    assert not (tmp_path / JOURNAL_NAME).exists()
    assert target.read_bytes() == b'done'
    # A same-named file outside the mapped subtree cannot complete the folder.
    target.unlink()
    (tmp_path / 'file').write_bytes(b'done')
    folders = m.inspect_folders(tmp_path, [folder], {}, tree.__getitem__)
    assert folders[folder.href]['status'] == 'partial'
    # Ambiguous full-path versus flattened copies must not be treated as confirmed.
    alternative = tmp_path / ('album' if relative == 'remote/album' else 'remote/album')
    alternative.mkdir(parents=True)
    folders = m.inspect_folders(tmp_path, [folder], {}, tree.__getitem__)
    assert folders[folder.href]['status'] == 'attention'


@pytest.mark.parametrize('problem', ['changed', 'short', 'symlink', 'missing-empty', 'new-file', 'new-folder', 'unavailable'])
def test_folder_scan_never_confirms_incomplete_or_unchecked_trees(tmp_path, problem):
    folder = m.Entry('/archive', 'archive', True)
    nested = m.Entry('/archive/nested', 'nested', True)
    empty = m.Entry('/archive/empty', 'empty', True)
    file = m.Entry('/archive/nested/file', 'file', False, 4, etag='"v1"')
    target = tmp_path / 'archive/nested/file'
    target.parent.mkdir(parents=True)
    target.write_bytes(b'done')
    (tmp_path / 'archive/empty').mkdir()
    journal = DownloadJournal(tmp_path, 'account')
    journal.register([(file, target)])
    journal.update(target, 'complete', published=target)
    tree = {'/': [folder], folder.href: [nested, empty], nested.href: [file], empty.href: []}
    def listing(path):
        if problem == 'unavailable' and path == nested.href:
            raise OSError('listing unavailable')
        return tree[path]
    if problem == 'changed':
        tree[nested.href] = [m.Entry(file.href, file.name, False, 4, etag='"v2"')]
    elif problem == 'short':
        target.write_bytes(b'd')
    elif problem == 'symlink':
        target.unlink()
        outside = tmp_path / 'outside'
        outside.write_bytes(b'done')
        target.symlink_to(outside)
    elif problem == 'missing-empty':
        (tmp_path / 'archive/empty').rmdir()
    elif problem == 'new-file':
        tree[nested.href].append(m.Entry('/archive/nested/new', 'new', False, 4, etag='"v1"'))
    elif problem == 'new-folder':
        tree[folder.href].append(m.Entry('/archive/new', 'new', True))
    files = inspect_destination(tmp_path, 'account', [folder], listing)
    folders = m.inspect_folders(tmp_path, [folder], files, listing)
    assert folders[folder.href]['status'] in ('partial', 'attention')
    assert folders[folder.href]['status'] != 'complete'
    assert m.inspect_folders(tmp_path, [folder], files, listing, lambda: True) == {}


def test_journal_does_not_follow_symlink_or_write_on_scan(tmp_path):
    outside = tmp_path / 'outside'
    outside.mkdir()
    destination = tmp_path / 'downloads'
    destination.mkdir()
    (destination / JOURNAL_NAME).symlink_to(outside / 'journal')
    journal = DownloadJournal(destination, 'source')
    with pytest.raises(ValueError, match='Symlink'): journal.records()
    with pytest.raises(ValueError, match='Symlink'): journal.register([])
    assert not (outside / 'journal').exists()


@pytest.mark.parametrize('folder_error', [False, True])
def test_file_colors_appear_before_slow_folder_scan_finishes(tmp_path, folder_error):
    folder = m.Entry('/archive', 'archive', True)
    done = m.Entry('/done', 'done', False, 4, etag='"v1"')
    found = m.Entry('/found', 'found', False, 4, etag='"v1"')
    nested = m.Entry('/archive/nested', 'nested', False, 4, etag='"v1"')
    entered, release = threading.Event(), threading.Event()
    (tmp_path / 'archive').mkdir()
    for relative in ('done', 'found', 'archive/nested'):
        (tmp_path / relative).write_bytes(b'done')
    class Fake:
        auth = ('color-account', 'key')
        def list(self, path):
            if path == '/': return [folder, done, found]
            assert path == folder.href
            entered.set()
            assert release.wait(5), 'folder listing was not released'
            if folder_error: raise OSError('folder listing unavailable')
            return [nested]
    journal = DownloadJournal(tmp_path, source_id(m.BASE, Fake()))
    journal.register([(done, tmp_path / 'done')])
    journal.update(tmp_path / 'done', 'complete', published=tmp_path / 'done')
    async def check():
        app = m.CloudApp(Fake())
        async with app.run_test(size=(100, 28)) as pilot:
            app.query_one('#destination', m.Input).value = str(tmp_path)
            try:
                assert await asyncio.to_thread(entered.wait, 2)
                await pilot.pause(.05)
                assert app.recovery_scanning
                table = app.query_one('#table', m.DataTable)
                assert table.get_row(done.href)[1].style == '#7f8793'
                assert table.get_row(done.href)[-1].plain == 'Скачан'
                assert table.get_row(found.href)[1].style == '#e5c07b'
                assert table.get_row(found.href)[-1].plain == 'Найден на диске'
                assert not app.selected
                assert str(app.query_one('#show-resume', m.Button).label) == 'Докачка'
            finally:
                release.set()
            await wait_for_scan(app, pilot)
            assert table.get_row(done.href)[1].style == '#7f8793'
            assert table.get_row(found.href)[1].style == '#e5c07b'
            assert table.get_row(folder.href)[-1].plain == ('Требует проверки' if folder_error else 'Найдена на диске')
            assert set(app.recovery) == {'done', 'found'}
    asyncio.run(check())


@pytest.mark.parametrize('stage', ['inspect_destination', 'inspect_folders'])
def test_background_scan_does_not_freeze_or_apply_old_destination(tmp_path, monkeypatch, stage):
    entered, release = threading.Event(), threading.Event()
    original = getattr(m, stage)
    first, second = tmp_path / 'first', tmp_path / 'second'
    first.mkdir(); second.mkdir()
    (first / 'file').write_bytes(b'done')
    entry = m.Entry('/file', 'file', False, 4, etag='"v1"')
    def slow(destination, *args):
        if destination == first:
            entered.set()
            assert release.wait(5)
        return original(destination, *args)
    monkeypatch.setattr(m, stage, slow)
    class Fake:
        def list(self, path): return [entry]
    journal = DownloadJournal(first, source_id(m.BASE, Fake()))
    journal.register([(entry, first / 'file')])
    journal.update(first / 'file', 'complete', published=first / 'file')
    async def check():
        app = m.CloudApp(Fake())
        async with app.run_test(size=(80, 24)) as pilot:
            app.query_one('#destination', m.Input).value = str(first)
            assert await asyncio.to_thread(entered.wait, 2)
            await pilot.click('#toggle-credentials')
            assert app.query_one('#credentials').has_class('open')
            app.query_one('#destination', m.Input).value = str(second)
            release.set()
            await wait_for_scan(app, pilot)
            assert app.recovery_destination == second
            assert app.recovery == {}
            assert app.downloaded == {}
            assert app.query_one('#table', m.DataTable).get_row(entry.href)[1].style == ''
    try:
        asyncio.run(check())
    finally:
        release.set()


def test_navigation_checks_camera_files_without_recursive_rescan(tmp_path, monkeypatch):
    folder = m.Entry('/Camera Uploads', 'Camera Uploads', True)
    nested = m.Entry('/Camera Uploads/nested', 'nested', True)
    file = m.Entry('/Camera Uploads/file', 'file', False, 4, etag='"v1"')
    entries = [file, nested]
    calls, folder_scans = Counter(), []
    original = m.inspect_folders
    def folders(*args):
        folder_scans.append(True)
        return original(*args)
    monkeypatch.setattr(m, 'inspect_folders', folders)
    class Fake:
        def list(self, path):
            calls[path] += 1
            return [folder] if path == '/' else entries[:] if path == folder.href else []
    target = tmp_path / 'Camera Uploads/file'
    target.parent.mkdir()
    (target.parent / 'nested').mkdir()
    target.write_bytes(b'done')
    journal = DownloadJournal(tmp_path, source_id(m.BASE, Fake()))
    journal.register([(file, target)])
    journal.update(target, 'complete', published=target)
    async def check():
        app = m.CloudApp(Fake())
        app.dest = tmp_path
        async with app.run_test(size=(80, 24)) as pilot:
            await wait_for_scan(app, pilot)
            assert folder_scans == [True]
            table = app.query_one('#table', m.DataTable)
            assert table.get_row(folder.href)[1].style == '#7f8793'
            app.action_open()
            assert app.recovery_scanning
            await wait_for_scan(app, pilot)
            assert folder_scans == [True]
            assert calls == {'/': 1, folder.href: 1, nested.href: 1}
            assert table.get_row(file.href)[1].style == '#7f8793'
            assert table.get_row(nested.href)[1].style == '#7f8793'
            assert 'Каталог проверен' in app.sync_status
            # The explicit command also refreshes cloud metadata, not just the cache.
            entries[0] = m.Entry(file.href, file.name, False, 5, etag='"v2"')
            await pilot.click('#sync')
            await wait_for_scan(app, pilot)
            assert folder_scans == [True, True]
            assert calls[folder.href] == 2
            assert table.get_row(file.href)[1].style != '#7f8793'
            assert file.href not in app.downloaded
            assert 'Сверка завершена' in app.sync_status
    asyncio.run(check())


def test_quick_scan_invalidates_stale_parent_folder_mark(tmp_path):
    folder = m.Entry('/folder', 'folder', True)
    file = m.Entry('/folder/file', 'file', False, 4, etag='"v1"')
    class Fake:
        def list(self, path): return [folder] if path == '/' else [file]
    target = tmp_path / 'folder/file'
    target.parent.mkdir()
    target.write_bytes(b'done')
    journal = DownloadJournal(tmp_path, source_id(m.BASE, Fake()))
    journal.register([(file, target)])
    journal.update(target, 'complete', published=target)
    async def check():
        app = m.CloudApp(Fake())
        app.dest = tmp_path
        async with app.run_test(size=(80, 24)) as pilot:
            await wait_for_scan(app, pilot)
            assert app.entry_cells(folder)[1].style == '#7f8793'
            target.unlink()
            app.action_open()
            await wait_for_scan(app, pilot)
            app.action_back()
            await wait_for_scan(app, pilot)
            row = app.query_one('#table', m.DataTable).get_row(folder.href)
            assert row[1].style == '#e5c07b'
            assert row[-1].plain == 'Требует проверки'
            await pilot.click('#sync')
            await wait_for_scan(app, pilot)
            row = app.query_one('#table', m.DataTable).get_row(folder.href)
            assert row[1].style == '#e5c07b'
            assert row[-1].plain == 'Частично'
    asyncio.run(check())


@pytest.mark.parametrize('stage', ['load', 'inspect_destination', 'inspect_folders'])
def test_sync_indicator_and_stop_discard_late_results(tmp_path, monkeypatch, stage):
    folder = m.Entry('/Camera Uploads', 'Camera Uploads', True)
    file = m.Entry('/file', 'file', False, 4, etag='"v1"')
    entered, release, blocking, finished = (threading.Event() for _ in range(4))
    (tmp_path / folder.name).mkdir()
    target = tmp_path / file.name
    target.write_bytes(b'done')
    class Fake:
        def list(self, path):
            if stage == 'load' and path == '/' and blocking.is_set():
                entered.set()
                assert release.wait(5)
                finished.set()
            return [folder, file] if path == '/' else []
    if stage != 'load':
        original = getattr(m, stage)
        def slow(*args):
            result = original(*args)
            if blocking.is_set():
                entered.set()
                assert release.wait(5)
                finished.set()
            return result
        monkeypatch.setattr(m, stage, slow)
    journal = DownloadJournal(tmp_path, source_id(m.BASE, Fake()))
    journal.register([(file, target)])
    journal.update(target, 'complete', published=target)
    async def check():
        app = m.CloudApp(Fake())
        app.dest = tmp_path
        async with app.run_test(size=(80, 24)) as pilot:
            await wait_for_scan(app, pilot)
            assert app.downloaded[file.href] == file
            target.unlink()
            blocking.set()
            await pilot.click('#sync')
            assert await asyncio.to_thread(entered.wait, 2)
            await pilot.pause(.05)
            assert app.recovery_scanning
            status = app.query_one('#sync-status', m.Static)
            assert ' с' in str(status.render())
            button = app.query_one('#sync', m.Button)
            assert str(button.label) == 'Остановить'
            assert app.screen.region.contains_region(button.region)
            assert not button.region.overlaps(status.region)
            assert app.query_one('#table', m.DataTable).region.height >= 16
            # The network/disk operation is blocked; the rest of the UI still works.
            await pilot.click('#toggle-credentials')
            assert app.query_one('#credentials').has_class('open')
            await pilot.click('#toggle-credentials')
            snapshot, badges = app.recovery, app.recovery_by_href.copy()
            await pilot.click('#sync')
            assert not app.recovery_scanning
            assert str(button.label) == 'Сверить'
            assert 'прервана' in str(status.render())
            release.set()
            assert await asyncio.to_thread(finished.wait, 2)
            await pilot.pause(.3)
            assert not app.recovery_scanning
            assert app.recovery is snapshot
            assert app.recovery_by_href == badges
            assert 'прервана' in str(status.render())
    try:
        asyncio.run(check())
    finally:
        release.set()
