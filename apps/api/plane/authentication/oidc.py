# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""Small OIDC boundary: existing requests + PyJWT; no provider tokens persisted."""

import base64
import hashlib
import json
import logging
import secrets
import time
import uuid
from datetime import timedelta
from urllib.parse import urlencode, urlsplit

import jwt
import requests
from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import IntegrityError, transaction
from django.utils import timezone

from plane.db.models import OIDCIdentity, OIDCLoginTransaction, Profile, User
from plane.license.models import InstanceAdmin
from plane.utils.path_validator import validate_next_path

logger = logging.getLogger(__name__)
ALGORITHMS = ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512")


class OIDCError(Exception):
    """Safe failure code; never include tokens, code, secret or upstream responses."""


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def check_url(url, same_origin=None):
    try:
        parsed = urlsplit(url)
        origin = (parsed.scheme, parsed.hostname, parsed.port)
    except (ValueError, TypeError) as exc:
        raise OIDCError("invalid_configuration") from exc
    insecure_test = settings.DEBUG and settings.OIDC_ALLOW_INSECURE_HTTP
    if (
        not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
        or parsed.scheme not in ({"https", "http"} if insecure_test else {"https"})
        or (same_origin and origin != check_url(same_origin))
    ):
        raise OIDCError("invalid_configuration")
    return origin


def configuration(target="app"):
    if not settings.OIDC_ENABLED:
        raise OIDCError("disabled")
    if not all((settings.OIDC_ISSUER, settings.OIDC_CLIENT_ID, settings.OIDC_CLIENT_SECRET)):
        raise OIDCError("invalid_configuration")
    check_url(settings.OIDC_ISSUER)
    redirect = settings.OIDC_ADMIN_REDIRECT_URI if target == "admin" else settings.OIDC_REDIRECT_URI
    check_url(redirect)
    if not 60 <= settings.OIDC_SESSION_MAX_AGE <= 86400:
        raise OIDCError("invalid_configuration")
    return redirect


def fetch_json(url, *, data=None):
    """No redirects, bounded response, TLS verification, connect/read timeout."""
    try:
        with requests.Session() as session:
            # Do not leak IdP credentials to implicit .netrc or environment proxies.
            session.trust_env = False
            with session.request(
                "POST" if data is not None else "GET",
                url,
                data=data,
                headers={"Accept": "application/json"},
                timeout=(5, 10),
                allow_redirects=False,
                stream=True,
            ) as response:
                if response.status_code != 200:
                    raise OIDCError("provider_unavailable")
                raw = bytearray()
                for chunk in response.iter_content(8192):
                    raw.extend(chunk)
                    if len(raw) > 1048576:
                        raise OIDCError("invalid_provider_response")
                result = json.loads(raw)
                if not isinstance(result, dict):
                    raise OIDCError("invalid_provider_response")
                return result
    except (requests.RequestException, ValueError) as exc:
        raise OIDCError("provider_unavailable") from exc


def discovery():
    url = settings.OIDC_DISCOVERY_URL or settings.OIDC_ISSUER.rstrip("/") + "/.well-known/openid-configuration"
    check_url(url, settings.OIDC_ISSUER)
    key = "oidc:metadata:" + digest(url + settings.OIDC_ISSUER)
    metadata = cache.get(key)
    if metadata is None:
        metadata = fetch_json(url)
        if metadata.get("issuer") != settings.OIDC_ISSUER:
            raise OIDCError("issuer_mismatch")
        for endpoint in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            check_url(metadata.get(endpoint), settings.OIDC_ISSUER)
        if "S256" not in metadata.get("code_challenge_methods_supported", []):
            raise OIDCError("pkce_not_supported")
        if "client_secret_post" not in metadata.get("token_endpoint_auth_methods_supported", []):
            raise OIDCError("client_secret_post_not_supported")
        cache.set(key, metadata, 300)
    return metadata


def begin(request, target, *, purpose="login"):
    redirect = configuration(target)
    metadata = discovery()
    if not request.session.session_key:
        request.session.create()
    state, nonce, verifier = (secrets.token_urlsafe(48) for _ in range(3))
    now = timezone.now()
    OIDCLoginTransaction.objects.filter(expires_at__lt=now).delete()
    # A browser has one outstanding transaction; re-starting cannot grow the table.
    session_hash = digest(request.session.session_key)
    OIDCLoginTransaction.objects.filter(session_hash=session_hash).delete()
    OIDCLoginTransaction.objects.create(
        state_hash=digest(state),
        session_hash=session_hash,
        nonce=nonce,
        verifier=verifier,
        redirect_uri=redirect,
        target=target,
        purpose=purpose,
        user=request.user if purpose == "link" else None,
        expires_at=now + timedelta(minutes=5),
        next_path=validate_next_path((request.POST if purpose == "link" else request.GET).get("next_path", ""))
        if target == "app"
        else "",
    )
    scopes = set(settings.OIDC_SCOPES.split()) | {"openid", "email"}
    scopes.discard("offline_access")
    params = {
        "client_id": settings.OIDC_CLIENT_ID,
        "redirect_uri": redirect,
        "response_type": "code",
        "scope": " ".join(sorted(scopes)),
        "state": state,
        "nonce": nonce,
        "code_challenge_method": "S256",
        "code_challenge": base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode(),
    }
    if purpose == "link":
        # Require a new IdP authentication, not a silent login in a shared browser.
        params.update(prompt="login", max_age="0")
    return metadata["authorization_endpoint"] + "?" + urlencode(params)


def consume(request, target):
    state = request.GET.get("state", "")
    if not state or len(state) > 256 or not request.session.session_key:
        raise OIDCError("invalid_state")
    with transaction.atomic():
        pending = OIDCLoginTransaction.objects.select_for_update().filter(state_hash=digest(state)).first()
        if pending is None:
            raise OIDCError("invalid_state")
        valid = (
            secrets.compare_digest(pending.session_hash, digest(request.session.session_key))
            and (pending.target == target or (target == "app" and pending.target == "space"))
            and pending.expires_at > timezone.now()
        )
        # Delete in a committed transaction even when validation/exchange fails.
        if valid:
            pending.delete()
    if not valid:
        raise OIDCError("invalid_state")
    return pending


def signing_key(metadata, token):
    header = jwt.get_unverified_header(token)
    algorithm, kid = header.get("alg"), header.get("kid")
    if algorithm not in ALGORITHMS or not isinstance(kid, str) or not kid or len(kid) > 255:
        raise OIDCError("invalid_token")
    if algorithm not in metadata.get("id_token_signing_alg_values_supported", []):
        raise OIDCError("invalid_token")
    key = "oidc:jwks:" + digest(metadata["jwks_uri"])
    jwks = cache.get(key)
    if jwks is None:
        jwks = fetch_json(metadata["jwks_uri"])
        cache.set(key, jwks, 300)
    candidates = jwks.get("keys", [])
    if not any(k.get("kid") == kid for k in candidates):
        # Unknown kid triggers one refresh per 10s, across workers (Redis cache).
        if cache.add(key + ":refresh", True, 10):
            jwks = fetch_json(metadata["jwks_uri"])
            cache.set(key, jwks, 300)
            candidates = jwks.get("keys", [])
    matches = [k for k in candidates if k.get("kid") == kid and k.get("use", "sig") == "sig"]
    if len(matches) != 1 or matches[0].get("alg", algorithm) != algorithm:
        raise OIDCError("invalid_token")
    return jwt.PyJWK.from_dict(matches[0], algorithm=algorithm).key, algorithm


def exchange(request, pending):
    configuration(pending.target)
    code = request.GET.get("code", "")
    if request.GET.get("error") or not code or len(code) > 4096:
        raise OIDCError("authorization_failed")
    metadata = discovery()
    result = fetch_json(
        metadata["token_endpoint"],
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": settings.OIDC_CLIENT_ID,
            "client_secret": settings.OIDC_CLIENT_SECRET,
            "redirect_uri": pending.redirect_uri,
            "code_verifier": pending.verifier,
        },
    )
    token = result.get("id_token")
    if not isinstance(token, str) or len(token) > 32768:
        raise OIDCError("invalid_token")
    try:
        key, algorithm = signing_key(metadata, token)
        claims = jwt.decode(
            token,
            key,
            algorithms=[algorithm],
            issuer=settings.OIDC_ISSUER,
            audience=settings.OIDC_CLIENT_ID,
            leeway=0,
            options={"require": ["iss", "sub", "aud", "exp", "iat", "nonce"]},
        )
        if not isinstance(claims["nonce"], str) or not secrets.compare_digest(claims["nonce"], pending.nonce):
            raise OIDCError("invalid_nonce")
        if getattr(pending, "purpose", "login") == "link":
            auth_time = claims.get("auth_time")
            if not isinstance(auth_time, (int, float)) or not 0 <= time.time() - auth_time <= 300:
                raise OIDCError("idp_reauthentication_required")
        audiences = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
        if (len(audiences) > 1 or "azp" in claims) and claims.get("azp") != settings.OIDC_CLIENT_ID:
            raise OIDCError("invalid_token")
        if not claims["sub"] or len(claims["sub"]) > 255:
            raise OIDCError("invalid_token")
        if not isinstance(claims["iat"], (int, float)) or time.time() - claims["iat"] > 600:
            raise OIDCError("invalid_token")
        # OIDC at_hash is optional in the code flow, but must validate if present.
        if "at_hash" in claims:
            access = result.get("access_token", "")
            hash_fn = getattr(hashlib, "sha" + algorithm[-3:])
            hashed = hash_fn(access.encode()).digest()
            expected = base64.urlsafe_b64encode(hashed[: len(hashed) // 2]).rstrip(b"=").decode()
            if not secrets.compare_digest(expected, claims["at_hash"]):
                raise OIDCError("invalid_token")
        return claims
    except (jwt.PyJWTError, ValueError, TypeError, KeyError, AttributeError) as exc:
        raise OIDCError("invalid_token") from exc


def verified_email(claims):
    email = claims.get("email")
    if claims.get("email_verified") is not True or not isinstance(email, str) or len(email) > 255:
        raise OIDCError("verified_email_required")
    email = email.strip().lower()
    try:
        validate_email(email)
    except ValidationError as exc:
        raise OIDCError("verified_email_required") from exc
    allowed = {domain.strip().lower() for domain in settings.OIDC_ALLOWED_EMAIL_DOMAINS.split(",") if domain.strip()}
    if allowed and email.rsplit("@", 1)[1] not in allowed:
        raise OIDCError("email_domain_not_allowed")
    return email


@transaction.atomic
def resolve_user(claims, target="app"):
    email = verified_email(claims)
    identity = OIDCIdentity.objects.select_related("user").filter(issuer=claims["iss"], subject=claims["sub"]).first()
    if identity:
        user = identity.user
        # Do not rewrite Plane email or memberships when the IdP changes claims.
        if not user.is_active or user.is_bot:
            raise OIDCError("account_disabled")
    else:
        if User.objects.filter(email__iexact=email).exists():
            raise OIDCError("account_link_required")
        if target == "admin" or not settings.OIDC_AUTO_PROVISION:
            raise OIDCError("provisioning_disabled")
        try:
            with transaction.atomic():
                user = User(
                    email=email,
                    username=uuid.uuid4().hex,
                    is_email_verified=True,
                    is_password_autoset=True,
                    first_name=str(claims.get("given_name", ""))[:255],
                    last_name=str(claims.get("family_name", ""))[:255],
                )
                user.set_unusable_password()
                user.save()
                Profile.objects.create(user=user)
                OIDCIdentity.objects.create(issuer=claims["iss"], subject=claims["sub"], user=user)
        except IntegrityError as exc:
            # Concurrent provisioning is retried as a fresh login, never email-linked.
            raise OIDCError("provisioning_conflict") from exc
        logger.info("oidc_user_provisioned user_id=%s", user.pk)
    if target == "admin" and not InstanceAdmin.objects.filter(user=user).exists():
        raise OIDCError("admin_required")
    # No groups/roles/workspace claims are ever read, and no memberships granted.
    user.last_login_medium = "oidc"
    user.last_login_time = timezone.now()
    user.last_active = timezone.now()
    user.save(update_fields=["last_login_medium", "last_login_time", "last_active"])
    return user
