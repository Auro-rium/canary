"""Ownership verification: all three methods, with no real network or DNS."""

import httpx
import pytest

from cyberredteam.security import ownership
from cyberredteam.security.ownership import (
    DNS_TXT,
    HTTP_WELLKNOWN,
    RESPONSE_HEADER,
    VERIFY_HEADER,
    TargetRefused,
    check_target_url,
    verify_ownership,
)
from cyberredteam.security.tokens import hash_verification_token, issue_verification_token

ENDPOINT = "https://agent.example.com/v1/chat"
PUBLIC_IP = "93.184.216.34"


@pytest.fixture
def token():
    return issue_verification_token()


@pytest.fixture
def token_hash(token):
    return hash_verification_token(token)


def public_resolver(_host):
    return [PUBLIC_IP]


def no_network_resolver(_host):  # pragma: no cover - must never be reached
    raise AssertionError("resolver must not be called")


def run(method, handler=None, *, endpoint=ENDPOINT, token_hash, **kw):
    kw.setdefault("resolve_host", public_resolver)
    transport = httpx.MockTransport(handler) if handler else None
    return verify_ownership(endpoint, token_hash, method, transport=transport, **kw)


# ── http_wellknown ───────────────────────────────────────────────────────────


def test_wellknown_success(token, token_hash):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, text=f"{token}\n")

    result = run(HTTP_WELLKNOWN, handler, token_hash=token_hash)
    assert result.verified, result.reason
    assert str(seen[0].url) == "https://agent.example.com/.well-known/canary-verify.txt"
    assert seen[0].method == "GET"


def test_wellknown_wrong_token(token_hash):
    result = run(
        HTTP_WELLKNOWN,
        lambda r: httpx.Response(200, text=issue_verification_token()),
        token_hash=token_hash,
    )
    assert not result.verified
    assert "does not contain" in result.reason


def test_wellknown_404(token_hash):
    result = run(HTTP_WELLKNOWN, lambda r: httpx.Response(404), token_hash=token_hash)
    assert not result.verified and "404" in result.reason


def test_wellknown_timeout(token_hash):
    def handler(request):
        raise httpx.ConnectTimeout("slow", request=request)

    result = run(HTTP_WELLKNOWN, handler, token_hash=token_hash)
    assert not result.verified and result.reason == "timeout"


def test_wellknown_redirect_to_other_host_refused(token, token_hash):
    calls = []

    def handler(request):
        calls.append(str(request.url))
        if request.url.host == "agent.example.com":
            return httpx.Response(302, headers={"location": "https://evil.example.net/tok"})
        return httpx.Response(200, text=token)

    result = run(HTTP_WELLKNOWN, handler, token_hash=token_hash)
    assert not result.verified
    assert "another host" in result.reason
    assert len(calls) == 1  # the other host is never contacted


def test_wellknown_same_host_redirect_followed(token, token_hash):
    def handler(request):
        if request.url.path == "/.well-known/canary-verify.txt":
            return httpx.Response(301, headers={"location": "/static/verify.txt"})
        return httpx.Response(200, text=token)

    assert run(HTTP_WELLKNOWN, handler, token_hash=token_hash).verified


def test_wellknown_https_downgrade_refused(token, token_hash):
    def handler(request):
        if request.url.scheme == "https":
            return httpx.Response(302, headers={"location": "http://agent.example.com/v"})
        return httpx.Response(200, text=token)

    result = run(HTTP_WELLKNOWN, handler, token_hash=token_hash)
    assert not result.verified and "https to http" in result.reason


def test_wellknown_redirect_loop_capped(token_hash):
    result = run(
        HTTP_WELLKNOWN,
        lambda r: httpx.Response(302, headers={"location": "/again"}),
        token_hash=token_hash,
    )
    assert not result.verified and "too many redirects" in result.reason


def test_wellknown_reason_never_echoes_body(token_hash):
    body = "SENSITIVE-BODY-CONTENT"
    result = run(HTTP_WELLKNOWN, lambda r: httpx.Response(200, text=body), token_hash=token_hash)
    assert body not in result.reason


# ── dns_txt ──────────────────────────────────────────────────────────────────


def test_dns_success(token, token_hash):
    asked = []

    def txt(name, timeout):
        asked.append((name, timeout))
        return ["v=spf1 -all", token]

    result = run(DNS_TXT, txt_resolver=txt, token_hash=token_hash)
    assert result.verified, result.reason
    assert asked[0][0] == "_canary-verify.agent.example.com"
    assert asked[0][1] <= ownership.DEFAULT_TIMEOUT_S


def test_dns_wrong_token(token_hash):
    result = run(
        DNS_TXT, txt_resolver=lambda n, t: [issue_verification_token()], token_hash=token_hash
    )
    assert not result.verified and "no matching TXT" in result.reason


def test_dns_no_record(token_hash):
    result = run(DNS_TXT, txt_resolver=lambda n, t: [], token_hash=token_hash)
    assert not result.verified


def test_dns_timeout(token_hash):
    def txt(name, timeout):
        raise TimeoutError

    result = run(DNS_TXT, txt_resolver=txt, token_hash=token_hash)
    assert not result.verified and result.reason == "timeout"


def test_dns_resolver_error_fails_closed(token_hash):
    def txt(name, timeout):
        raise OSError("boom")

    result = run(DNS_TXT, txt_resolver=txt, token_hash=token_hash)
    assert not result.verified and "DNS lookup failed" in result.reason


def test_dns_ip_literal_rejected(token, token_hash):
    result = run(
        DNS_TXT,
        endpoint=f"https://{PUBLIC_IP}/chat",
        txt_resolver=lambda n, t: [token],
        token_hash=token_hash,
    )
    assert not result.verified and "hostname" in result.reason


def test_dns_private_target_refused(token, token_hash):
    result = run(
        DNS_TXT,
        txt_resolver=lambda n, t: [token],
        resolve_host=lambda h: ["10.1.2.3"],
        token_hash=token_hash,
    )
    assert not result.verified and result.reason.startswith("refused")


def test_default_txt_resolver_maps_timeout(monkeypatch):
    import dns.exception
    import dns.resolver

    def boom(self, *a, **k):
        raise dns.exception.Timeout

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", boom)
    with pytest.raises(TimeoutError):
        ownership.default_txt_resolver("_canary-verify.example.com", 1.0)


def test_default_txt_resolver_nxdomain_is_empty(monkeypatch):
    import dns.resolver

    def nx(self, *a, **k):
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", nx)
    assert ownership.default_txt_resolver("_canary-verify.example.com", 1.0) == []


# ── response_header ──────────────────────────────────────────────────────────


def test_header_success_on_get(token, token_hash):
    methods = []

    def handler(request):
        methods.append(request.method)
        return httpx.Response(200, headers={VERIFY_HEADER: token})

    result = run(RESPONSE_HEADER, handler, token_hash=token_hash)
    assert result.verified, result.reason
    assert methods == ["GET"]


def test_header_falls_back_to_benign_post(token, token_hash):
    seen = []

    def handler(request):
        seen.append((request.method, request.content))
        if request.method == "GET":
            return httpx.Response(405)
        return httpx.Response(200, headers={VERIFY_HEADER: token}, json={"reply": "hi"})

    result = run(RESPONSE_HEADER, handler, token_hash=token_hash)
    assert result.verified, result.reason
    assert seen == [("GET", b""), ("POST", b"{}")]


def test_header_wrong_token(token_hash):
    result = run(
        RESPONSE_HEADER,
        lambda r: httpx.Response(200, headers={VERIFY_HEADER: "nope"}),
        token_hash=token_hash,
    )
    assert not result.verified and "does not match" in result.reason


def test_header_missing(token_hash):
    result = run(RESPONSE_HEADER, lambda r: httpx.Response(200), token_hash=token_hash)
    assert not result.verified and "did not return" in result.reason


def test_header_timeout(token_hash):
    def handler(request):
        raise httpx.ReadTimeout("slow", request=request)

    result = run(RESPONSE_HEADER, handler, token_hash=token_hash)
    assert not result.verified and result.reason == "timeout"


def test_header_redirect_to_other_host_refused(token, token_hash):
    def handler(request):
        if request.url.host == "agent.example.com":
            return httpx.Response(307, headers={"location": "https://other.example.org/chat"})
        return httpx.Response(200, headers={VERIFY_HEADER: token})

    result = run(RESPONSE_HEADER, handler, token_hash=token_hash)
    assert not result.verified and "another host" in result.reason


def test_header_connect_error_fails_closed(token_hash):
    def handler(request):
        raise httpx.ConnectError("refused", request=request)

    result = run(RESPONSE_HEADER, handler, token_hash=token_hash)
    assert not result.verified and "request failed" in result.reason


# ── private / loopback / link-local guard ────────────────────────────────────


@pytest.mark.parametrize("method", [HTTP_WELLKNOWN, DNS_TXT, RESPONSE_HEADER])
@pytest.mark.parametrize(
    "endpoint",
    [
        "http://127.0.0.1:9000/chat",
        "http://10.0.0.5/chat",
        "http://192.168.1.10/chat",
        "http://169.254.169.254/latest/meta-data",
        "http://[::1]/chat",
        "http://localhost:9000/chat",
        "http://api.localhost/chat",
        "http://metadata.google.internal/",
        "http://2130706433/chat",
    ],
)
def test_private_targets_refused(method, endpoint, token, token_hash):
    def handler(request):  # pragma: no cover - must never be reached
        raise AssertionError("private target was contacted")

    result = run(
        method,
        handler,
        endpoint=endpoint,
        resolve_host=no_network_resolver,
        txt_resolver=lambda n, t: [token],
        token_hash=token_hash,
    )
    assert not result.verified
    assert result.reason.startswith("refused")


@pytest.mark.parametrize("addresses", [["127.0.0.1"], ["10.0.0.1"], [PUBLIC_IP, "192.168.0.1"], ["fe80::1"]])
def test_hostname_resolving_to_private_refused(addresses, token, token_hash):
    def handler(request):  # pragma: no cover
        raise AssertionError("private target was contacted")

    result = run(
        HTTP_WELLKNOWN, handler, resolve_host=lambda h: addresses, token_hash=token_hash
    )
    assert not result.verified and "non-public" in result.reason


def test_unresolvable_host_fails_closed(token_hash):
    def resolver(host):
        raise OSError("nxdomain")

    result = run(HTTP_WELLKNOWN, lambda r: httpx.Response(200), resolve_host=resolver, token_hash=token_hash)
    assert not result.verified and "could not resolve" in result.reason


def test_redirect_to_private_ip_refused(token, token_hash):
    def handler(request):
        return httpx.Response(302, headers={"location": "http://127.0.0.1/x"})

    result = run(HTTP_WELLKNOWN, handler, token_hash=token_hash)
    assert not result.verified and result.reason.startswith("refused")


def test_allow_private_targets_explicit_opt_in(token, token_hash):
    result = run(
        RESPONSE_HEADER,
        lambda r: httpx.Response(200, headers={VERIFY_HEADER: token}),
        endpoint="http://localhost:9000/chat",
        resolve_host=no_network_resolver,
        allow_private_targets=True,
        token_hash=token_hash,
    )
    assert result.verified, result.reason


@pytest.mark.parametrize(
    "url",
    ["ftp://agent.example.com/", "https://user:pw@agent.example.com/", "https://agent.example.com/#x"],
)
def test_bad_url_forms_refused(url):
    with pytest.raises(TargetRefused):
        check_target_url(url, resolve_host=public_resolver)


def test_unknown_method_rejected(token_hash):
    with pytest.raises(ValueError):
        verify_ownership(ENDPOINT, token_hash, "carrier_pigeon")


def test_missing_token_hash_fails(token):
    result = verify_ownership(ENDPOINT, "", HTTP_WELLKNOWN, resolve_host=public_resolver)
    assert not result.verified


# ── auth URL host binding ────────────────────────────────────────────────────


class _Auth:
    def __init__(self, **urls):
        self.__dict__.update(urls)


def test_auth_url_same_host_ok():
    ownership.check_target_urls(
        ENDPOINT, _Auth(token_url="https://agent.example.com/oauth/t"), resolve_host=public_resolver
    )


def test_auth_url_sibling_subdomain_needs_listing():
    auth = _Auth(token_url="https://auth.example.com/t")
    with pytest.raises(TargetRefused, match="allowed_auth_hosts"):
        ownership.check_target_urls(ENDPOINT, auth, resolve_host=public_resolver)
    ownership.check_target_urls(ENDPOINT, auth, ["auth.example.com"], resolve_host=public_resolver)


def test_auth_url_cross_tenant_on_shared_hosting_refused():
    with pytest.raises(TargetRefused):
        ownership.check_target_urls(
            "https://victim.herokuapp.com/chat",
            _Auth(token_url="https://attacker.herokuapp.com/token"),
            resolve_host=public_resolver,
        )


def test_auth_url_foreign_domain_refused_unless_listed():
    auth = _Auth(login_url="https://evil.example.net/login")
    with pytest.raises(TargetRefused, match="allowed_auth_hosts"):
        ownership.check_target_urls(ENDPOINT, auth, resolve_host=public_resolver)
    ownership.check_target_urls(ENDPOINT, auth, ["evil.example.net"], resolve_host=public_resolver)


def test_auth_url_private_refused_even_if_listed():
    auth = _Auth(token_url="http://10.0.0.1/token")
    with pytest.raises(TargetRefused, match="token_url"):
        ownership.check_target_urls(ENDPOINT, auth, ["10.0.0.1"], resolve_host=public_resolver)


def test_auth_url_non_http_refused():
    with pytest.raises(TargetRefused):
        ownership.check_target_urls(
            ENDPOINT, _Auth(token_url="file:///etc/passwd"), resolve_host=public_resolver
        )


def test_auth_url_private_allowed_with_explicit_flag():
    ownership.check_target_urls(
        "http://localhost:9000/chat",
        _Auth(token_url="http://localhost:9001/token"),
        allow_private_targets=True,
    )
