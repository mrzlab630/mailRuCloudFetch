"""Keep tests from reading or writing a real user's destination preferences."""
import pytest
import cloudmail_downloader as downloader


@pytest.fixture(autouse=True)
def isolated_download_session(tmp_path, monkeypatch):
    monkeypatch.setattr(downloader, 'SESSION_STATE', tmp_path / 'private-session' / 'session.json')
