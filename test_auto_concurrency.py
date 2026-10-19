import asyncio
import threading

import pytest

import cloudmail_downloader as m
from download_state import DownloadJournal, source_id
from test_download_recovery import wait_for_batch
from test_download_session import wait_for_scan


@pytest.mark.parametrize('sizes,expected', [
    ([], 0), ([1024], 1), ([None], 1), ([None] * 20, 2),
    ([1024] * 20, 8), ([8 * 1024**2] * 20, 4), ([128 * 1024**2] * 20, 2),
])
def test_initial_parallelism_matches_queue_size_and_file_sizes(sizes, expected):
    policy = m.AutoConcurrency(sizes)
    assert policy.limit == expected
    assert policy.limit <= policy.maximum <= min(16, len(sizes))


def test_speed_probe_keeps_gain_and_reverts_plateau():
    policy = m.AutoConcurrency([128 * 1024**2] * 40)
    policy.observe(0, 0, 0, True)
    policy.observe(8, 800, 0, True)
    assert policy.limit == 4
    policy.observe(16, 2400, 0, True)
    assert policy.limit == 4  # Doubling produced twice the total throughput.
    policy.observe(24, 4000, 0, True)
    assert policy.limit == 8
    policy.observe(32, 5600, 0, True)
    assert policy.limit == 4  # Eight gave no gain over four.
    for now in range(40, 105, 8):
        policy.observe(now, now * 200, 0, True)
        assert policy.limit == 4


def test_limits_cooldown_and_paused_or_underfilled_measurements():
    policy = m.AutoConcurrency([1024] * 100)
    policy.observe(0, 0, 0, True)
    policy.observe(8, 800, 0, True)
    assert policy.limit == 16
    policy.observe(16, 2400, 0, True)
    assert policy.limit == 16
    policy.observe(17, 2400, 1, True)
    assert policy.limit == 8
    for now in (18, 26, 34, 42):
        policy.observe(now, now * 200, 1, True)
        assert policy.limit == 8  # A past error is not a new error every poll.
    policy.observe(43, 9000, 2, True)
    assert policy.limit == 4
    policy.observe(44, 9000, 3, True)
    assert policy.limit == 2
    policy.observe(45, 9000, 4, True)
    policy.observe(46, 9000, 5, True)
    assert policy.limit == 1
    policy.observe(100, 9000, 5, True, paused=True)
    policy.observe(200, 9000, 5, True, paused=True)
    assert policy.limit == 1
    policy.observe(201, 9000, 5, True)
    policy.observe(202, 9000, 5, False)
    policy.observe(300, 19000, 5, False)
    assert policy.limit == 1  # Neither pause nor queue tail can trigger a probe.


def test_stalled_probe_reverts_without_waiting_for_an_error():
    policy = m.AutoConcurrency([8 * 1024**2] * 20)
    policy.observe(0, 0, 0, True)
    policy.observe(8, 800, 0, True)
    assert policy.limit == 8
    policy.observe(16, 800, 0, True)
    assert policy.limit == 4


def test_auto_queue_measures_across_refills_and_drains_on_backoff(tmp_path, monkeypatch):
    app = m.CloudApp(None)
    entries = [m.Entry('/' + str(i), str(i), False, 128 * 1024**2) for i in range(8)]
    jobs = [(entry, tmp_path / entry.name) for entry in entries]
    app.states = {entry.href: [0, entry.bytes, 0, 'Ожидает', ''] for entry in entries}
    releases = [threading.Event() for _ in entries]
    changed = threading.Condition()
    started, failures, observed = [], [], []
    logical_now = [0]
    original = m.AutoConcurrency
    class TimedPolicy(original):
        def observe(self, now, received, errors, saturated, paused=False):
            super().observe(logical_now[0], received, errors, saturated, paused)
            with changed:
                observed.append((logical_now[0], self.limit, saturated))
                changed.notify_all()
    monkeypatch.setattr(m, 'AutoConcurrency', TimedPolicy)
    def download(entry, target):
        with changed:
            started.append(int(entry.name))
            changed.notify_all()
        assert releases[int(entry.name)].wait(5)
    app.download_one = download
    def run():
        try: app.run_auto_queue(jobs, [entry.bytes for entry in entries])
        except BaseException as exc: failures.append(exc)
    runner = threading.Thread(target=run)
    runner.start()
    try:
        with changed:
            assert changed.wait_for(lambda: len(started) == 2 and any(n == 0 and full for n, _, full in observed), 3)
        with app.lock:
            app.received = 400
            logical_now[0] = 4
        releases[0].set()
        with changed:
            assert changed.wait_for(lambda: len(started) == 3, 3)
        with app.lock:
            app.received = 800
            logical_now[0] = 8
        with changed:
            assert changed.wait_for(lambda: len(started) == 5, 3)
        with app.lock:
            app.temporary_failures = 1
            logical_now[0] = 9
        with changed:
            assert changed.wait_for(lambda: any(n == 9 and limit == 2 for n, limit, _ in observed), 3)
            assert len(started) == 5
        # Lowering the target must not abort any of the four active files.
        releases[1].set(); releases[2].set()
        with changed:
            assert changed.wait_for(lambda: observed[-1] == (9, 2, True), 3)
            assert len(started) == 5
        releases[3].set()
        with changed:
            assert changed.wait_for(lambda: len(started) == 6, 3)
    finally:
        for event in releases: event.set()
        runner.join(5)
    assert not runner.is_alive()
    assert not failures
    assert sorted(started) == list(range(8))
    assert app.parallel_active == 0


def test_paused_queue_does_not_start_more_files_and_stop_preserves_pending(tmp_path, monkeypatch):
    app = m.CloudApp(None)
    entries = [m.Entry('/' + str(i), str(i), False, 128 * 1024**2) for i in range(12)]
    app.states = {entry.href: [0, entry.bytes, 0, 'Ожидает', ''] for entry in entries}
    app.paused = True
    changed, release = threading.Condition(), threading.Event()
    started, observed, failures = [], [], []
    original = m.AutoConcurrency
    class ObservedPolicy(original):
        def observe(self, *args):
            super().observe(*args)
            with changed:
                observed.append(args[-1])
                changed.notify_all()
    monkeypatch.setattr(m, 'AutoConcurrency', ObservedPolicy)
    def download(entry, target):
        with changed:
            started.append(entry.href)
            changed.notify_all()
        assert release.wait(5)
        with app.lock: app.states[entry.href][3] = 'Готово'
    app.download_one = download
    def run():
        try: app.run_auto_queue([(e, tmp_path / e.name) for e in entries], [e.bytes for e in entries])
        except BaseException as exc: failures.append(exc)
    runner = threading.Thread(target=run)
    runner.start()
    try:
        with changed:
            assert changed.wait_for(lambda: observed, 3)
            assert not started
        app.paused = False
        with changed:
            assert changed.wait_for(lambda: len(started) == 2, 3)
            observed.clear()
        app.paused = True
        with changed:
            assert changed.wait_for(lambda: any(observed), 3)
        release.set()
        app.stop.set()
        runner.join(3)
    finally:
        release.set(); app.stop.set(); runner.join(3)
    assert not runner.is_alive()
    assert not failures
    assert len(started) == 2
    assert sum(state[3] == 'Остановлено' for state in app.states.values()) == 10
    assert not app.error_jobs


def test_auto_ui_counts_only_pending_files_and_keeps_compact_layout(tmp_path):
    entries = [m.Entry('/' + str(i), str(i), False, 4, etag='"v1"') for i in range(6)]
    entered, release = threading.Event(), threading.Event()
    calls = []
    class Fake:
        def list(self, path): return entries
        def get(self, entry, target, update, cancelled):
            calls.append(entry.href)
            if len(calls) == 2: entered.set()
            update(0, 4, 0)
            assert release.wait(5)
            if cancelled(): return False
            target.write_bytes(b'done')
            update(4, 4, 1)
            return True
    journal = DownloadJournal(tmp_path, source_id(m.BASE, Fake()))
    for entry in entries[:4]:
        target = tmp_path / entry.name
        target.write_bytes(b'done')
        journal.register([(entry, target)])
        journal.update(target, 'complete', published=target)
    async def check():
        app = m.CloudApp(Fake())
        app.dest = tmp_path
        async with app.run_test(size=(80, 24)) as pilot:
            await wait_for_scan(app, pilot)
            assert not app.query('#threads')
            assert app.query_one('#destination').region.right >= 79
            app.selected = {entry.href: entry for entry in entries}
            app.action_download()
            try:
                assert await asyncio.to_thread(entered.wait, 3)
                app.progress()
                assert 'Авто: 2/2' in app.transfer_status
                assert app.parallel_limit == 2  # Four confirmed files need no workers.
                await pilot.click('#toggle-credentials')
                assert app.query_one('#credentials').has_class('open')
                assert app.screen.region.contains_region(app.query_one('#stop-download').region)
            finally:
                release.set()
            await wait_for_batch(app, pilot)
            assert sorted(calls) == ['/4', '/5']
            assert all(state[3] == 'Готово' for state in app.states.values())
            assert app.received == 8
            assert not app.selected
            assert all((tmp_path / entry.name).read_bytes() == b'done' for entry in entries)
    try: asyncio.run(check())
    finally: release.set()
