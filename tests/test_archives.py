import py7zr

from protectarr.archives import inspect
from conftest import make_zip


def test_plain_zip(tmp_path):
    p = make_zip(tmp_path / "a.zip", {"movie.mkv": b"x"})
    info = inspect(str(p), "zip")
    assert info.entries == ["movie.mkv"] and not info.encrypted


def test_encrypted_zip(tmp_path):
    p = make_zip(tmp_path / "a.zip", {"movie.mkv": b"x"}, encrypted=True)
    assert inspect(str(p), "zip").encrypted


def test_encrypted_7z_with_hidden_names(tmp_path):
    p = tmp_path / "a.7z"
    with py7zr.SevenZipFile(p, "w", password="secret", header_encryption=True) as sz:
        sz.writestr(b"payload", "setup.exe")
    assert inspect(str(p), "7z").encrypted


def test_corrupt_archive_reports_error(tmp_path):
    p = tmp_path / "bad.zip"
    p.write_bytes(b"PK\x03\x04garbage")
    assert inspect(str(p), "zip").error
