# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Django imports
from django.contrib.auth import login
from django.conf import settings
import time

# Module imports
from plane.utils.host import base_host
from plane.utils.ip_address import get_client_ip


def user_login(request, user, is_app=False, is_admin=False, is_space=False):
    login(request=request, user=user)

    # Fresh proof belongs to this browser session, never to User.last_login_time.
    # OIDC login must not be mistaken for proof of the existing local account.
    request.session.pop("oidc_link_confirmation", None)
    if request.path.startswith(("/auth/oidc/", "/api/instances/oidc/")):
        request.session.pop("account_auth", None)
    else:
        request.session["account_auth"] = {"user_id": str(user.pk), "at": int(time.time())}

    # If is admin cookie set the custom age
    if is_admin:
        request.session.set_expiry(settings.ADMIN_SESSION_COOKIE_AGE)

    device_info = {
        "user_agent": request.META.get("HTTP_USER_AGENT", ""),
        "ip_address": get_client_ip(request=request),
        "domain": base_host(request=request, is_app=is_app, is_admin=is_admin, is_space=is_space),
    }
    request.session["device_info"] = device_info
    request.session.save()
    return
