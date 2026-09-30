import zipfile

import pytest

MKV = b"\x1a\x45\xdf\xa3" + b"\x00" * 1024
PE = b"MZ\x90\x00" + b"\x00" * 1024
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def make_zip(path, entries, encrypted=False):
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    if encrypted:
        # zipfile can't write encrypted entries, so set the "encrypted" flag bit in the headers.
        # Listing only reads headers, so the plaintext data doesn't matter.
        raw = bytearray(open(path, "rb").read())
        for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            i = raw.find(sig)
            while i != -1:
                raw[i + off] |= 0x1
                i = raw.find(sig, i + 4)
        open(path, "wb").write(bytes(raw))
    return path


@pytest.fixture
def mkv_bytes():
    return MKV
