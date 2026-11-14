# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import logging
import time

from django.conf import settings
from django.contrib.auth import logout
from django.http import JsonResponse

logger = logging.getLogger(__name__)


def recovery_allowed(request):
    remaining = settings.OIDC_ADMIN_RECOVERY_UNTIL - time.time()
    ips = {ip.strip() for ip in settings.OIDC_ADMIN_RECOVERY_IPS.split(",") if ip.strip()}
    return 0 < remaining <= 900 and request.META.get("REMOTE_ADDR") in ips


class OIDCPolicyMiddleware:
    """Enforce exclusivity server-side, including previously issued local sessions."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        marker = request.session.get("oidc_auth")
        if marker and (
            not settings.OIDC_ENABLED
            or marker.get("issuer") != settings.OIDC_ISSUER
            or marker.get("expires", 0) <= time.time()
            or not request.user.is_authenticated
        ):
            logout(request)

        if settings.OIDC_ENABLED and not settings.OIDC_ALLOW_LOCAL_LOGIN:
            admin = request.path.startswith("/api/instances/")
            recovery = admin and recovery_allowed(request)
            if request.user.is_authenticated and not request.session.get("oidc_auth") and not recovery:
                logout(request)
            allowed_auth = request.path.startswith("/auth/oidc/") or request.path in {
                "/auth/sign-out/",
                "/auth/spaces/sign-out/",
                "/auth/get-csrf-token/",
            }
            blocked = (request.path.startswith("/auth/") and not allowed_auth) or request.path in {
                "/api/instances/admins/sign-in/",
                "/api/instances/admins/sign-up/",
                "/api/instances/email-credentials-check/",
            }
            if blocked and not recovery:
                return JsonResponse({"error": "oidc_login_required"}, status=403)
            if blocked and recovery:
                logger.warning("oidc_admin_recovery_used socket_ip=%s", request.META.get("REMOTE_ADDR"))
        return self.get_response(request)
