import pytest

from webscan.core.http import default_port, normalize_target, same_origin


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("example.com", "https://example.com/"),
        ("https://example.com", "https://example.com/"),
        ("http://example.com/path", "http://example.com/path"),
        ("  example.com/a  ", "https://example.com/a"),
        ("https://example.com:8443/x", "https://example.com:8443/x"),
    ],
)
def test_normalize_target(given, expected):
    assert normalize_target(given) == expected


@pytest.mark.parametrize("bad", ["", "   ", "ftp://example.com", "https://"])
def test_normalize_target_rejects_bad_input(bad):
    with pytest.raises(ValueError):
        normalize_target(bad)


def test_default_port_follows_scheme_and_explicit_port():
    assert default_port("https://a.b/") == "443/tcp"
    assert default_port("http://a.b/") == "80/tcp"
    assert default_port("https://a.b:8443/") == "8443/tcp"


def test_same_origin_compares_scheme_and_host():
    assert same_origin("https://a.b/x", "https://a.b/y")
    assert not same_origin("https://a.b/x", "http://a.b/x")
    assert not same_origin("https://a.b/x", "https://c.b/x")
