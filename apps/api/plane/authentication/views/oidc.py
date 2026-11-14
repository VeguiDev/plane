# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import logging
import time
from datetime import datetime, timezone
from urllib.parse import urlencode

from django.conf import settings
from django.contrib.auth import logout
from django.http import HttpResponseRedirect, JsonResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect

from plane.authentication import oidc, oidc_link
from plane.authentication.rate_limit import authentication_throttle_allows
from plane.authentication.utils.host import base_host
from plane.authentication.utils.login import user_login
from plane.authentication.utils.user_auth_workflow import post_user_auth_workflow
from plane.license.models import Instance
from plane.utils.path_validator import get_safe_redirect_url
from plane.db.models import OIDCIdentity

logger = logging.getLogger(__name__)


def target_for(request):
    return "admin" if request.path.startswith("/api/instances/") else "app"


def failure(exc):
    logger.warning("oidc_login_failed reason=%s", exc)
    response = JsonResponse({"error": str(exc)}, status=400)
    response["Referrer-Policy"] = "no-referrer"
    return response


def link_page(reason="", next_path=""):
    # Internal fixed route: no provider identifiers or tokens in browser URLs.
    params = urlencode({"reason": reason, "next_path": next_path})
    response = HttpResponseRedirect(settings.APP_BASE_URL.rstrip("/") + "/sso-link?" + params)
    response["Referrer-Policy"] = "no-referrer"
    return response


@method_decorator(never_cache, name="dispatch")
class OIDCStartEndpoint(View):
    def get(self, request):
        if not authentication_throttle_allows(request):
            return JsonResponse({"error": "rate_limit_exceeded"}, status=429)
        if not Instance.objects.filter(is_setup_done=True).exists():
            return JsonResponse({"error": "instance_not_configured"}, status=409)
        try:
            target = target_for(request)
            if target == "app" and request.GET.get("target") == "space":
                target = "space"
            response = HttpResponseRedirect(oidc.begin(request, target))
            response["Referrer-Policy"] = "no-referrer"
            return response
        except oidc.OIDCError as exc:
            return failure(exc)


@method_decorator(never_cache, name="dispatch")
class OIDCCallbackEndpoint(View):
    def get(self, request):
        if not authentication_throttle_allows(request):
            return JsonResponse({"error": "rate_limit_exceeded"}, status=429)
        target = target_for(request)
        pending = None
        try:
            # Consume before network access: replay and concurrent callbacks fail.
            pending = oidc.consume(request, target)
            target = pending.target
            if pending.purpose == "link":
                oidc_link.require_recent_account_auth(request)
                if pending.user_id != request.user.pk or target != "app":
                    raise oidc.OIDCError("invalid_state")
            claims = oidc.exchange(request, pending)
            if pending.purpose == "link":
                oidc_link.prepare_confirmation(request, pending, claims)
                return link_page(next_path=pending.next_path)
            user = oidc.resolve_user(claims, target)
            if target != "admin" and user.is_email_verified and user.email == oidc.verified_email(claims):
                post_user_auth_workflow(user, False, request)
            user_login(request, user, is_app=target == "app", is_admin=target == "admin", is_space=target == "space")
            expires = int(time.time()) + min(
                settings.OIDC_SESSION_MAX_AGE, settings.ADMIN_SESSION_COOKIE_AGE if target == "admin" else 86400
            )
            request.session["oidc_auth"] = {"issuer": claims["iss"], "expires": expires}
            request.session.set_expiry(datetime.fromtimestamp(expires, tz=timezone.utc))
            response = HttpResponseRedirect(
                get_safe_redirect_url(
                    base_url=base_host(
                        request, is_app=target == "app", is_admin=target == "admin", is_space=target == "space"
                    ),
                    next_path=pending.next_path,
                )
            )
            response["Referrer-Policy"] = "no-referrer"
            logger.info("oidc_login_succeeded user_id=%s target=%s", user.pk, target)
            return response
        except oidc.OIDCError as exc:
            if str(exc) == "account_link_required" or (pending is not None and pending.purpose == "link"):
                logger.warning("oidc_link_flow_failed reason=%s", exc)
                return link_page(str(exc), pending.next_path if pending else "")
            return failure(exc)


@method_decorator([never_cache, csrf_protect], name="dispatch")
class OIDCLinkEndpoint(View):
    def get(self, request):
        if not request.user.is_authenticated:
            return JsonResponse({"error": "authentication_required"}, status=401)
        recent = True
        try:
            oidc_link.require_recent_account_auth(request)
        except oidc.OIDCError:
            recent = False
        pending = oidc_link.pending_confirmation(request)
        return JsonResponse(
            {
                "enabled": settings.OIDC_ENABLED,
                "linked": OIDCIdentity.objects.filter(user=request.user, issuer=settings.OIDC_ISSUER).exists(),
                "recent_auth": recent,
                "account_email": request.user.email,
                "identity_email": pending.email if pending else None,
            }
        )

    def post(self, request):
        if not authentication_throttle_allows(request):
            return JsonResponse({"error": "rate_limit_exceeded"}, status=429)
        try:
            oidc_link.require_recent_account_auth(request)
            oidc_link.cancel(request)
            response = HttpResponseRedirect(oidc.begin(request, "app", purpose="link"))
            response["Referrer-Policy"] = "no-referrer"
            return response
        except oidc.OIDCError as exc:
            return link_page(str(exc))


@method_decorator([never_cache, csrf_protect], name="dispatch")
class OIDCLinkConfirmEndpoint(View):
    def post(self, request):
        if not authentication_throttle_allows(request):
            return JsonResponse({"error": "rate_limit_exceeded"}, status=429)
        try:
            oidc_link.confirm(request)
            return JsonResponse({"linked": True})
        except oidc.OIDCError as exc:
            return failure(exc)


@method_decorator([never_cache, csrf_protect], name="dispatch")
class OIDCLinkCancelEndpoint(View):
    def post(self, request):
        if not request.user.is_authenticated:
            return JsonResponse({"error": "authentication_required"}, status=401)
        oidc_link.cancel(request)
        return JsonResponse({"cancelled": True})


@method_decorator([never_cache, csrf_protect], name="dispatch")
class OIDCSessionEndpoint(View):
    def post(self, request):
        """Rotate the Plane session key without extending its absolute lifetime."""
        marker = request.session.get("oidc_auth")
        if not request.user.is_authenticated or not marker or marker["expires"] <= time.time():
            return JsonResponse({"error": "authentication_required"}, status=401)
        request.session.cycle_key()
        return JsonResponse({"expires_at": marker["expires"]})


@method_decorator([never_cache, csrf_protect], name="dispatch")
class OIDCLogoutEndpoint(View):
    def post(self, request):
        # Local logout is always effective, even when the IdP is unavailable.
        # No implicit global IdP logout or unsafe redirect parameter.
        logout(request)
        return JsonResponse({"logged_out": True})
