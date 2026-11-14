# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""Explicit self-service linking: independent proof of both accounts, no email matching."""

import time
from datetime import timedelta

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from plane.authentication import oidc
from plane.db.models import OIDCIdentity, OIDCLinkConfirmation, User

FRESH_SECONDS = 600


def require_recent_account_auth(request):
    marker = request.session.get("account_auth", {})
    now = time.time()
    if not request.user.is_authenticated or not request.user.is_active or request.user.is_bot:
        raise oidc.OIDCError("authentication_required")
    if (
        marker.get("user_id") != str(request.user.pk)
        or not isinstance(marker.get("at"), (int, float))
        or not 0 <= now - marker["at"] <= FRESH_SECONDS
    ):
        raise oidc.OIDCError("reauthentication_required")


def check_identity_available(user, issuer, subject):
    identities = OIDCIdentity.objects.filter(issuer=issuer)
    if identities.filter(subject=subject).exclude(user=user).exists():
        raise oidc.OIDCError("identity_already_linked")
    if identities.filter(user=user).exclude(subject=subject).exists():
        raise oidc.OIDCError("account_already_linked")


def prepare_confirmation(request, pending, claims):
    require_recent_account_auth(request)
    if pending.purpose != "link" or pending.user_id != request.user.pk or pending.target != "app":
        raise oidc.OIDCError("invalid_state")
    email = oidc.verified_email(claims)
    check_identity_available(request.user, claims["iss"], claims["sub"])
    now = timezone.now()
    OIDCLinkConfirmation.objects.filter(expires_at__lt=now).delete()
    OIDCLinkConfirmation.objects.filter(
        user=request.user, session_hash=oidc.digest(request.session.session_key)
    ).delete()
    confirmation = OIDCLinkConfirmation.objects.create(
        user=request.user,
        session_hash=oidc.digest(request.session.session_key),
        issuer=claims["iss"],
        subject=claims["sub"],
        email=email,
        expires_at=now + timedelta(minutes=5),
    )
    request.session["oidc_link_confirmation"] = str(confirmation.pk)


def pending_confirmation(request):
    return OIDCLinkConfirmation.objects.filter(
        pk=request.session.get("oidc_link_confirmation"),
        user=request.user,
        session_hash=oidc.digest(request.session.session_key or ""),
        issuer=settings.OIDC_ISSUER,
        expires_at__gt=timezone.now(),
    ).first()


def confirm(request):
    oidc.configuration("app")
    require_recent_account_auth(request)
    with transaction.atomic():
        # Serialize parallel attempts for this account, including different browsers.
        user = User.objects.select_for_update().get(pk=request.user.pk)
        if not user.is_active or user.is_bot:
            raise oidc.OIDCError("account_disabled")
        pending = pending_confirmation(request)
        if pending is None:
            raise oidc.OIDCError("confirmation_expired")
        check_identity_available(user, pending.issuer, pending.subject)
        try:
            with transaction.atomic():
                identity, created = OIDCIdentity.objects.get_or_create(
                    issuer=pending.issuer, subject=pending.subject, defaults={"user": user}
                )
        except IntegrityError as exc:
            raise oidc.OIDCError("link_conflict") from exc
        if identity.user_id != user.pk:
            raise oidc.OIDCError("identity_already_linked")
        pending.delete()
    request.session.pop("oidc_link_confirmation", None)
    request.session.cycle_key()
    oidc.logger.info("oidc_identity_self_linked user_id=%s identity_id=%s created=%s", user.pk, identity.pk, created)


def cancel(request):
    pending = pending_confirmation(request)
    if pending:
        pending.delete()
    request.session.pop("oidc_link_confirmation", None)
