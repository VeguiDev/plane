# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""OIDC security regression suite. All keys/identities are generated test data."""

import base64
import hashlib
import json
import time
from datetime import timedelta
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from django.core.cache import cache
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import Client, RequestFactory
from django.utils import timezone

from plane.authentication import oidc
from plane.authentication.middleware.oidc import recovery_allowed
from plane.db.models import (
    OIDCIdentity,
    OIDCLoginTransaction,
    Session,
    User,
    Workspace,
    WorkspaceMember,
    WorkspaceMemberInvite,
)
from plane.db.models.session import SessionStore
from plane.license.models import Instance, InstanceAdmin

pytestmark = pytest.mark.django_db
ISSUER = "https://idp.example/application/o/ancen/"


@pytest.fixture(autouse=True)
def oidc_settings(settings, mock_celery):
    settings.OIDC_ENABLED = True
    settings.OIDC_ISSUER = ISSUER
    settings.OIDC_DISCOVERY_URL = ISSUER + ".well-known/openid-configuration"
    settings.OIDC_CLIENT_ID = "test-plane"
    settings.OIDC_CLIENT_SECRET = "isolated-test-secret"
    settings.OIDC_REDIRECT_URI = "https://plane.example/auth/oidc/callback/"
    settings.OIDC_ADMIN_REDIRECT_URI = "https://plane.example/api/instances/oidc/callback/"
    settings.OIDC_AUTO_PROVISION = True
    settings.OIDC_ALLOW_LOCAL_LOGIN = True
    settings.OIDC_ALLOWED_EMAIL_DOMAINS = "example.com"
    settings.WEB_URL = "https://plane.example"
    settings.APP_BASE_URL = "https://plane.example"
    settings.ADMIN_BASE_URL = "https://plane.example"
    settings.SPACE_BASE_URL = "https://plane.example"
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def instance():
    return Instance.objects.create(
        instance_name="Test",
        instance_id="oidc-test",
        current_version="test",
        last_checked_at=timezone.now(),
        is_setup_done=True,
    )


@pytest.fixture
def keys():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
    jwk.update(kid="key-1", use="sig", alg="RS256")
    return private, jwk


@pytest.fixture
def metadata():
    return {
        "issuer": ISSUER,
        "authorization_endpoint": "https://idp.example/authorize",
        "token_endpoint": "https://idp.example/token",
        "jwks_uri": "https://idp.example/jwks",
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }


def claims(**overrides):
    return {
        "iss": ISSUER,
        "sub": "subject-1",
        "aud": "test-plane",
        "iat": int(time.time()),
        "exp": int(time.time()) + 300,
        "nonce": "test-nonce",
        "email": "one@example.com",
        "email_verified": True,
        **overrides,
    }


def pending(**overrides):
    return SimpleNamespace(
        target="app",
        nonce="test-nonce",
        redirect_uri="https://plane.example/auth/oidc/callback/",
        verifier="test-verifier",
        **overrides,
    )


def install_provider(monkeypatch, metadata, keys, payload=None, token=None):
    token = token or jwt.encode(payload or claims(), keys[0], algorithm="RS256", headers={"kid": keys[1]["kid"]})

    def fetch(url, *, data=None):
        if data is not None:
            assert data["client_secret"] == "isolated-test-secret"
            assert data["grant_type"] == "authorization_code"
            return {"id_token": token}
        return {"keys": [keys[1]]} if url == metadata["jwks_uri"] else metadata

    monkeypatch.setattr(oidc, "fetch_json", fetch)


def exchange():
    return oidc.exchange(RequestFactory().get("/auth/oidc/callback/", {"code": "test-code"}), pending())


def test_start_pkce_and_server_side_state(client, instance, monkeypatch, metadata, keys):
    install_provider(monkeypatch, metadata, keys)
    response = client.get("/auth/oidc/", {"next_path": "https://evil.example/"})
    assert response.status_code == 302
    query = parse_qs(urlsplit(response.url).query)
    row = OIDCLoginTransaction.objects.get()
    assert query["code_challenge_method"] == ["S256"]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(row.verifier.encode()).digest()).rstrip(b"=").decode()
    assert query["code_challenge"] == [challenge]
    assert row.state_hash == oidc.digest(query["state"][0])
    assert row.nonce == query["nonce"][0]
    assert "verifier" not in response.url
    assert response["Cache-Control"].find("no-store") >= 0


@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "https://evil.example"},
        {"aud": "another-client"},
        {"exp": int(time.time()) - 1},
        {"nonce": "wrong"},
        {"iat": int(time.time()) + 1000},
        {"sub": ""},
        {"aud": ["test-plane", "other"]},
        {"azp": "other"},
        {"at_hash": "bad"},
        {"nbf": int(time.time()) + 1000},
    ],
)
def test_invalid_claims(monkeypatch, metadata, keys, overrides):
    install_provider(monkeypatch, metadata, keys, claims(**overrides))
    with pytest.raises(oidc.OIDCError):
        exchange()


@pytest.mark.parametrize("missing", ["nonce", "iss", "sub", "aud", "exp", "iat"])
def test_required_claims(monkeypatch, metadata, keys, missing):
    payload = claims()
    del payload[missing]
    install_provider(monkeypatch, metadata, keys, payload)
    with pytest.raises(oidc.OIDCError):
        exchange()


def test_tampered_signature(monkeypatch, metadata, keys):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(claims(), other, algorithm="RS256", headers={"kid": "key-1"})
    install_provider(monkeypatch, metadata, keys, token=token)
    with pytest.raises(oidc.OIDCError):
        exchange()


def test_algorithm_confusion(monkeypatch, metadata, keys):
    token = jwt.encode(
        claims(), "attacker-secret-not-a-real-key-123456789", algorithm="HS256", headers={"kid": "key-1"}
    )
    install_provider(monkeypatch, metadata, keys, token=token)
    with pytest.raises(oidc.OIDCError):
        exchange()


def test_jwks_rotation(monkeypatch, metadata, keys):
    install_provider(monkeypatch, metadata, keys)
    cache.set("oidc:jwks:" + oidc.digest(metadata["jwks_uri"]), {"keys": [{"kid": "old-key"}]})
    assert exchange()["sub"] == "subject-1"


def test_discovery_issuer_and_endpoint_pinning(monkeypatch, metadata):
    monkeypatch.setattr(oidc, "fetch_json", lambda url: {**metadata, "issuer": "https://evil.example"})
    with pytest.raises(oidc.OIDCError):
        oidc.discovery()
    monkeypatch.setattr(oidc, "fetch_json", lambda url: {**metadata, "token_endpoint": "https://evil.example/token"})
    with pytest.raises(oidc.OIDCError):
        oidc.discovery()


@pytest.mark.parametrize(
    "url",
    ["http://idp.example", "https://user:pass@idp.example", "file:///etc/passwd", "https://idp.example/#fragment"],
)
def test_unsafe_provider_urls(url):
    with pytest.raises(oidc.OIDCError):
        oidc.check_url(url)


def start(client, monkeypatch, metadata, keys):
    install_provider(monkeypatch, metadata, keys)
    result = client.get("/auth/oidc/")
    return parse_qs(urlsplit(result.url).query)["state"][0]


def test_state_binding_expiry_and_replay(client, instance, monkeypatch, metadata, keys):
    state = start(client, monkeypatch, metadata, keys)
    assert Client().get("/auth/oidc/callback/", {"state": state, "code": "code"}).status_code == 400
    assert client.get("/auth/oidc/callback/", {"state": "wrong", "code": "code"}).status_code == 400
    row = OIDCLoginTransaction.objects.get()
    row.expires_at = timezone.now() - timedelta(seconds=1)
    row.save()
    assert client.get("/auth/oidc/callback/", {"state": state, "code": "code"}).status_code == 400
    row.expires_at = timezone.now() + timedelta(seconds=60)
    row.save()
    # Provider errors still consume valid state.
    assert client.get("/auth/oidc/callback/", {"state": state, "error": "access_denied"}).status_code == 400
    assert not OIDCLoginTransaction.objects.exists()
    assert client.get("/auth/oidc/callback/", {"state": state, "code": "code"}).status_code == 400


def test_provision_no_workspace_grants():
    user = oidc.resolve_user(claims(groups=["admins"], role=20, is_superuser=True))
    assert user.is_email_verified and not user.has_usable_password() and not user.is_staff
    assert not WorkspaceMember.objects.filter(member=user).exists()
    assert oidc.resolve_user(claims()).pk == user.pk
    assert OIDCIdentity.objects.count() == 1


def test_existing_email_never_links():
    user = User.objects.create_user(username="existing", email="one@example.com", password="password")
    with pytest.raises(oidc.OIDCError, match="account_link_required"):
        oidc.resolve_user(claims())
    assert not OIDCIdentity.objects.filter(user=user).exists()


def test_link_operator_confirmation_and_no_reassignment(settings):
    user = User.objects.create_user(username="existing", email="one@example.com")
    args = {"user_id": str(user.pk), "issuer": ISSUER, "subject": "subject-1"}
    with pytest.raises(CommandError):
        call_command("oidc_link_identity", **args)
    call_command("oidc_link_identity", confirm_identity_verified=True, **args)
    assert oidc.resolve_user(claims()).pk == user.pk
    other = User.objects.create_user(username="other", email="other@example.com")
    with pytest.raises(CommandError):
        call_command("oidc_link_identity", **{**args, "user_id": str(other.pk), "confirm_identity_verified": True})


@pytest.mark.parametrize(
    "overrides",
    [{"email_verified": False}, {"email_verified": "true"}, {"email": "one@evil.example"}, {"email": "invalid"}],
)
def test_email_policy(overrides):
    with pytest.raises(oidc.OIDCError):
        oidc.resolve_user(claims(**overrides))
    assert User.objects.count() == 0


def test_disabled_provisioning(settings):
    settings.OIDC_AUTO_PROVISION = False
    with pytest.raises(oidc.OIDCError):
        oidc.resolve_user(claims())


def test_subject_not_email_and_disabled_account():
    user = oidc.resolve_user(claims())
    assert oidc.resolve_user(claims(email="changed@example.com")).pk == user.pk
    user.refresh_from_db()
    assert user.email == "one@example.com"
    with pytest.raises(oidc.OIDCError, match="account_link_required"):
        oidc.resolve_user(claims(sub="other-subject"))
    user.is_active = False
    user.save()
    with pytest.raises(oidc.OIDCError, match="account_disabled"):
        oidc.resolve_user(claims())


@pytest.mark.parametrize(
    "path",
    [
        "/auth/sign-in/",
        "/auth/sign-up/",
        "/auth/magic-sign-in/",
        "/auth/spaces/sign-in/",
        "/auth/google/",
        "/auth/google/callback/",
        "/auth/reset-password/u/t/",
        "/auth/set-password/",
        "/api/instances/admins/sign-in/",
        "/api/instances/admins/sign-up/",
    ],
)
def test_oidc_only_blocks_alternative_backends(client, settings, path):
    settings.OIDC_ALLOW_LOCAL_LOGIN = False
    assert client.post(path).status_code == 403


def test_recovery_is_short_lived_socket_ip_only(settings):
    settings.OIDC_ADMIN_RECOVERY_UNTIL = int(time.time()) + 300
    settings.OIDC_ADMIN_RECOVERY_IPS = "127.0.0.1"
    assert recovery_allowed(RequestFactory().get("/", REMOTE_ADDR="127.0.0.1"))
    assert not recovery_allowed(RequestFactory().get("/", REMOTE_ADDR="10.0.0.1", HTTP_X_FORWARDED_FOR="127.0.0.1"))
    settings.OIDC_ADMIN_RECOVERY_UNTIL = int(time.time()) + 3600
    assert not recovery_allowed(RequestFactory().get("/", REMOTE_ADDR="127.0.0.1"))


def test_admin_requires_preexisting_grant(instance):
    user = oidc.resolve_user(claims())
    with pytest.raises(oidc.OIDCError, match="admin_required"):
        oidc.resolve_user(claims(), "admin")
    InstanceAdmin.objects.create(user=user, instance=instance)
    assert oidc.resolve_user(claims(), "admin").pk == user.pk


def test_callback_session_rotation_logout_and_replay(client, instance, monkeypatch, metadata, keys):
    state = start(client, monkeypatch, metadata, keys)
    old_key = client.cookies["session-id"].value
    row = OIDCLoginTransaction.objects.get()
    install_provider(monkeypatch, metadata, keys, claims(nonce=row.nonce))
    assert client.get("/auth/oidc/callback/", {"code": "code", "state": state}).status_code == 302
    key = client.cookies["session-id"].value
    assert key != old_key and not Session.objects.filter(pk=old_key).exists()
    session = SessionStore(key)
    deadline = session["oidc_auth"]["expires"]
    assert client.post("/auth/oidc/session/").json()["expires_at"] == deadline
    rotated = client.cookies["session-id"].value
    assert rotated != key and not Session.objects.filter(pk=key).exists()
    assert client.post("/auth/oidc/logout/").status_code == 200
    assert not Session.objects.filter(pk=rotated).exists()
    assert client.get("/auth/oidc/callback/", {"code": "code", "state": state}).status_code == 400


def test_csrf_on_rotation_and_logout():
    client = Client(enforce_csrf_checks=True)
    assert client.post("/auth/oidc/session/").status_code == 403
    assert client.post("/auth/oidc/logout/").status_code == 403


def test_absolute_expiry_invalidates_session(client):
    user = oidc.resolve_user(claims())
    client.force_login(user)
    session = client.session
    session["oidc_auth"] = {"issuer": ISSUER, "expires": int(time.time()) - 1}
    session.save()
    key = session.session_key
    assert client.get("/api/users/me/").status_code in {401, 403}
    assert not Session.objects.filter(pk=key).exists()


def test_exclusive_mode_invalidates_previous_local_session(client, settings):
    user = oidc.resolve_user(claims())
    client.force_login(user)
    settings.OIDC_ALLOW_LOCAL_LOGIN = False
    assert client.get("/api/users/me/").status_code in {401, 403}


@pytest.mark.django_db(transaction=True)
def test_concurrent_callbacks_consume_state_once(client, instance, monkeypatch, metadata, keys):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from types import SimpleNamespace
    from django.db import close_old_connections

    state = start(client, monkeypatch, metadata, keys)
    session_key = client.session.session_key
    barrier = Barrier(2)

    def consume():
        close_old_connections()
        try:
            barrier.wait(timeout=5)
            request = SimpleNamespace(GET={"state": state}, session=SimpleNamespace(session_key=session_key))
            try:
                oidc.consume(request, "app")
                return True
            except oidc.OIDCError:
                return False
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(lambda _: consume(), range(2))) == [False, True]
    assert not OIDCLoginTransaction.objects.exists()


def test_issuer_change_invalidates_session(client, settings):
    user = oidc.resolve_user(claims())
    client.force_login(user)
    session = client.session
    session["oidc_auth"] = {"issuer": ISSUER, "expires": int(time.time()) + 300}
    session.save()
    settings.OIDC_ISSUER = "https://different.example/"
    assert client.get("/api/users/me/").status_code in {401, 403}


def test_workspace_roles_and_isolation(client):
    user = oidc.resolve_user(claims())
    owner = User.objects.create_user(username="owner", email="owner@example.com")
    a = Workspace.objects.create(name="A", slug="isolated-a", owner=owner)
    b = Workspace.objects.create(name="B", slug="isolated-b", owner=owner)
    WorkspaceMember.objects.create(workspace=a, member=user, role=5)
    client.force_login(user)
    assert client.get(f"/api/workspaces/{a.slug}/members/").status_code == 200
    assert client.get(f"/api/workspaces/{b.slug}/members/").status_code in {403, 404}
    assert client.patch(
        f"/api/workspaces/{a.slug}/", data=json.dumps({"name": "hacked"}), content_type="application/json"
    ).status_code in {403, 404}
    assert not WorkspaceMember.objects.filter(workspace=b, member=user).exists()
    assert WorkspaceMember.objects.get(workspace=a, member=user).role == 5


def test_only_accepted_invitations(client, instance, monkeypatch, metadata, keys):
    owner = User.objects.create_user(username="owner", email="owner@example.com")
    a = Workspace.objects.create(name="A", slug="invite-a", owner=owner)
    b = Workspace.objects.create(name="B", slug="invite-b", owner=owner)
    WorkspaceMemberInvite.objects.create(email="one@example.com", workspace=a, role=15, accepted=True, token="a")
    WorkspaceMemberInvite.objects.create(email="one@example.com", workspace=b, role=20, accepted=False, token="b")
    state = start(client, monkeypatch, metadata, keys)
    row = OIDCLoginTransaction.objects.get()
    install_provider(monkeypatch, metadata, keys, claims(nonce=row.nonce))
    assert client.get("/auth/oidc/callback/", {"code": "code", "state": state}).status_code == 302
    user = User.objects.get(email="one@example.com")
    assert WorkspaceMember.objects.get(workspace=a, member=user).role == 15
    assert not WorkspaceMember.objects.filter(workspace=b, member=user).exists()


@pytest.mark.django_db(transaction=True)
def test_e2e_isolated_provider(live_server, settings, instance, keys):
    """Real HTTP discovery, authorization, PKCE token exchange, JWKS and session API."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread
    from urllib.parse import urlencode
    import requests

    authorizations = {}
    redirect_uri = live_server.url + "/auth/oidc/callback/"

    class Provider(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # Never log codes/tokens, even in this isolated test server.

        def respond(self, body, status=200):
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(body).encode())

        def do_GET(self):
            parsed = urlsplit(self.path)
            origin = f"http://127.0.0.1:{self.server.server_port}"
            if parsed.path.endswith("/.well-known/openid-configuration"):
                self.respond(
                    {
                        "issuer": origin + "/application/o/test/",
                        "authorization_endpoint": origin + "/authorize",
                        "token_endpoint": origin + "/token",
                        "jwks_uri": origin + "/jwks",
                        "code_challenge_methods_supported": ["S256"],
                        "token_endpoint_auth_methods_supported": ["client_secret_post"],
                        "id_token_signing_alg_values_supported": ["RS256"],
                    }
                )
            elif parsed.path == "/jwks":
                self.respond({"keys": [keys[1]]})
            elif parsed.path == "/authorize":
                query = parse_qs(parsed.query)
                assert query["response_type"] == ["code"]
                assert query["redirect_uri"] == [redirect_uri]
                assert query["code_challenge_method"] == ["S256"]
                authorizations["one-use-code"] = query
                self.send_response(302)
                self.send_header(
                    "Location", redirect_uri + "?" + urlencode({"code": "one-use-code", "state": query["state"][0]})
                )
                self.end_headers()
            else:
                self.respond({}, 404)

        def do_POST(self):
            params = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
            query = authorizations.pop(params["code"][0])
            verifier = params["code_verifier"][0]
            assert (
                base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
                == query["code_challenge"][0]
            )
            assert params["client_secret"] == ["isolated-test-secret"]
            assert params["redirect_uri"] == [redirect_uri]
            origin = f"http://127.0.0.1:{self.server.server_port}"
            token = jwt.encode(
                claims(iss=origin + "/application/o/test/", nonce=query["nonce"][0]),
                keys[0],
                algorithm="RS256",
                headers={"kid": keys[1]["kid"]},
            )
            self.respond({"id_token": token, "access_token": "test-only", "token_type": "Bearer"})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    settings.OIDC_ISSUER = f"http://127.0.0.1:{server.server_port}/application/o/test/"
    settings.OIDC_DISCOVERY_URL = settings.OIDC_ISSUER + ".well-known/openid-configuration"
    settings.OIDC_REDIRECT_URI = redirect_uri
    settings.OIDC_ALLOW_INSECURE_HTTP = True
    settings.DEBUG = True
    settings.SESSION_COOKIE_SECURE = False
    settings.WEB_URL = live_server.url
    settings.APP_BASE_URL = live_server.url
    try:
        with requests.Session() as browser:
            browser.trust_env = False
            start_response = browser.get(live_server.url + "/auth/oidc/", allow_redirects=False, timeout=10)
            assert start_response.status_code == 302
            authorized = browser.get(start_response.headers["Location"], allow_redirects=False, timeout=10)
            callback = browser.get(authorized.headers["Location"], allow_redirects=False, timeout=10)
            assert callback.status_code == 302
            assert callback.headers["Location"].startswith(live_server.url)
            me = browser.get(live_server.url + "/api/users/me/", timeout=10)
            assert me.status_code == 200
            assert me.json()["email"] == "one@example.com"
            replay = browser.get(authorized.headers["Location"], allow_redirects=False, timeout=10)
            assert replay.status_code == 400
            # Operator revocation of server-side session takes effect immediately.
            Session.objects.filter(user_id=str(User.objects.get(email="one@example.com").pk)).delete()
            assert browser.get(live_server.url + "/api/users/me/", timeout=10).status_code in {401, 403}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
