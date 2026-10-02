from protectarr.findings import Level
from protectarr.rules import TorrentFile as F, check_metadata

MB = 1024 * 1024
MIN = 30 * MB


def codes(v):
    return {f.code for f in v.findings}


def test_normal_episode_is_clean():
    v = check_metadata([F("Show.S01E01.1080p/Show.S01E01.1080p.mkv", 1500 * MB),
                        F("Show.S01E01.1080p/Show.S01E01.1080p.nfo", 2000),
                        F("Show.S01E01.1080p/Subs/English.srt", 50000),
                        F("Show.S01E01.1080p/Sample/sample.mkv", 20 * MB)], MIN)
    assert v.level == Level.CLEAN, v.findings


def test_executable_is_malicious():
    v = check_metadata([F("Movie/Movie.mkv", 900 * MB), F("Movie/Codec_Setup.exe", 2 * MB)], MIN)
    assert v.level == Level.MALICIOUS and "executable" in codes(v)


def test_double_extension():
    v = check_metadata([F("Movie.2026.1080p.mkv.exe", 700 * MB)], MIN)
    assert "double_extension" in codes(v) and v.level == Level.MALICIOUS


def test_shortcut_file():
    v = check_metadata([F("Movie/Movie.mp4.lnk", 2000), F("Movie/data.bin", 900 * MB)], MIN)
    assert v.level == Level.MALICIOUS


def test_rtlo_trick():
    v = check_metadata([F("Movie\u202evkm.exe", 700 * MB)], MIN)
    assert "rtlo" in codes(v)


def test_tiny_video_is_suspicious():
    v = check_metadata([F("Big.Movie.2026.2160p.mkv", 4 * MB)], 300 * MB)
    assert v.level == Level.SUSPICIOUS and "too_small" in codes(v)


def test_wmv_and_password_lure():
    v = check_metadata([F("Movie/Movie.wmv", 800 * MB), F("Movie/PASSWORD.txt", 100)], MIN)
    assert {"legacy_video", "lure_name"} <= codes(v)


def test_password_archive_release():
    v = check_metadata([F("Movie/Movie.zip", 900 * MB), F("Movie/Get password here.url", 100)], MIN)
    assert v.level == Level.SUSPICIOUS and {"archive", "lure_file", "no_video"} <= codes(v)


def test_scene_rar_allowed_when_enabled():
    files = [F("Rel/rel.rar", 50 * MB), F("Rel/rel.r00", 50 * MB), F("Rel/rel.r01", 50 * MB), F("Rel/rel.nfo", 1)]
    assert check_metadata(files, MIN).level == Level.SUSPICIOUS
    assert check_metadata(files, MIN, allow_archives=True).level == Level.CLEAN


def test_extra_blocked_extension():
    v = check_metadata([F("M/M.mkv", 900 * MB), F("M/thing.xyz", 1)], MIN, extra_blocked=["xyz"])
    assert v.level == Level.MALICIOUS


def test_allowed_extension_is_not_flagged():
    files = [F("M/M.mkv", 900 * MB), F("M/extras.iso", 4000 * MB), F("M/M.thing", 10)]
    assert {"disk_image", "unknown_type"} <= codes(check_metadata(files, MIN))
    assert check_metadata(files, MIN, allowed=[".iso", "THING"]).level == Level.CLEAN


def test_allowed_extension_keeps_name_tricks():
    v = check_metadata([F("M/M.mkv", 900 * MB), F("M/M.mkv.exe", 1), F("M/codec.iso", 1),
                        F("M/M‮vkm.iso", 1)], MIN, allowed=[".exe", ".iso"])
    assert {"double_extension", "lure_name", "rtlo"} <= codes(v) and v.level == Level.MALICIOUS


def test_allowed_program_and_legacy_video():
    assert check_metadata([F("M/M.mkv", 900 * MB), F("M/tool.exe", 1)], MIN, allowed=[".exe"]).level == Level.CLEAN
    # An allowed WMV still counts as the release's video, so the size check applies to it.
    assert check_metadata([F("M/M.wmv", 900 * MB)], MIN, allowed=[".wmv"]).level == Level.CLEAN
    assert "too_small" in codes(check_metadata([F("M/M.wmv", 2 * MB)], MIN, allowed=[".wmv"]))


def test_allowing_a_main_type_still_counts_it():
    assert check_metadata([F("M/M.mkv", 900 * MB)], MIN, allowed=[".mkv"]).level == Level.CLEAN
