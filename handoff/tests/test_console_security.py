"""Security regressions for the desktop-only Hermes browser console.

These tests exercise HTTP traffic against a real loopback listener. They do not
run the agent or open any network-facing listener.
"""
import json
import tempfile
import urllib.error
import urllib.request

import pytest

from test_unpair import _console


@pytest.fixture
def console():
    with tempfile.TemporaryDirectory() as tmp:
        broker, url = _console(tmp)
        try:
            yield broker, url
        finally:
            broker.stop()


def request(url, path, method="GET", headers=None):
    req = urllib.request.Request(
        url + path,
        method=method,
        data=b"" if method == "POST" else None,
        headers=headers or {},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status, json.loads(response.read()), response.headers
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read()), error.headers


def test_get_cannot_reopen_pairing(console):
    broker, url = console
    assert not broker._pairing_open()
    status, _, _ = request(url, "/api/open-pairing")
    assert status == 405
    assert not broker._pairing_open()


def test_post_pairing_requires_console_header(console):
    broker, url = console
    status, _, _ = request(url, "/api/open-pairing", "POST")
    assert status == 403
    assert not broker._pairing_open()
    status, body, _ = request(
        url, "/api/open-pairing", "POST", {"X-Hermes-Console": "1"}
    )
    assert status == 200 and body["ok"] is True
    assert broker._pairing_open()


def test_dns_rebinding_host_cannot_read_history_or_open_pairing(console):
    broker, url = console
    status, _, _ = request(
        url, "/api/status", headers={"Host": "rebinding.example.test"}
    )
    assert status == 403
    status, _, _ = request(
        url,
        "/api/open-pairing",
        "POST",
        {"Host": "rebinding.example.test", "X-Hermes-Console": "1"},
    )
    assert status == 403
    assert not broker._pairing_open()


def test_cross_origin_post_cannot_open_pairing(console):
    broker, url = console
    status, _, _ = request(
        url,
        "/api/open-pairing",
        "POST",
        {
            "X-Hermes-Console": "1",
            "Origin": "https://attacker.example.test",
        },
    )
    assert status == 403
    assert not broker._pairing_open()


def test_sensitive_status_disables_caching(console):
    _, url = console
    status, _, headers = request(url, "/api/status")
    assert status == 200
    assert headers["Cache-Control"] == "no-store"
    assert headers["X-Content-Type-Options"] == "nosniff"


def test_unpair_rejects_non_object_and_oversized_body(console):
    broker, url = console
    for body, expected in [(b'[]', 400), (b'{"did":42}', 400),
                           (b' ' * 4097, 413)]:
        req = urllib.request.Request(url + "/api/unpair", method="POST",
            data=body, headers={"X-Hermes-Console":"1", "Content-Type":"application/json"})
        with pytest.raises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(req, timeout=5)
        assert caught.value.code == expected
    assert not broker._pairing_open()


def test_pairing_rejects_unexpected_body(console):
    broker, url = console
    req = urllib.request.Request(url + "/api/open-pairing", method="POST", data=b'{}',
        headers={"X-Hermes-Console":"1", "Content-Type":"application/json"})
    with pytest.raises(urllib.error.HTTPError) as caught:
        urllib.request.urlopen(req, timeout=5)
    assert caught.value.code == 400
    assert not broker._pairing_open()
