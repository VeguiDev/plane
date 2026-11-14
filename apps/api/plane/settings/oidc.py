# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""Instance-wide OIDC settings. Secrets are environment-only, never public config."""

import os


def flag(name, default="false"):
    return os.environ.get(name, default).lower() in {"true", "1"}


OIDC_ENABLED = flag("OIDC_ENABLED")
OIDC_ALLOW_LOCAL_LOGIN = flag("OIDC_ALLOW_LOCAL_LOGIN", "true")
OIDC_AUTO_PROVISION = flag("OIDC_AUTO_PROVISION", "true")
OIDC_SHOW_BUTTON = flag("OIDC_SHOW_BUTTON", "true")
OIDC_PROVIDER_NAME = os.environ.get("OIDC_PROVIDER_NAME", "Ancen SSO")
OIDC_BUTTON_TEXT = os.environ.get("OIDC_BUTTON_TEXT", "Continuar con Ancen SSO")
OIDC_ISSUER = os.environ.get("OIDC_ISSUER", "")
OIDC_DISCOVERY_URL = os.environ.get("OIDC_DISCOVERY_URL", "")
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "")
OIDC_REDIRECT_URI = os.environ.get("OIDC_REDIRECT_URI", "")
OIDC_ADMIN_REDIRECT_URI = os.environ.get("OIDC_ADMIN_REDIRECT_URI", "")
OIDC_SCOPES = os.environ.get("OIDC_SCOPES", "openid profile email")
OIDC_ALLOWED_EMAIL_DOMAINS = os.environ.get("OIDC_ALLOWED_EMAIL_DOMAINS", "")
OIDC_SESSION_MAX_AGE = int(os.environ.get("OIDC_SESSION_MAX_AGE", "28800"))
# Only for an isolated test IdP; additionally requires Django DEBUG=True.
OIDC_ALLOW_INSECURE_HTTP = flag("OIDC_ALLOW_INSECURE_HTTP")
# Break-glass only: epoch deadline (at most 15 minutes ahead) and exact socket IPs.
OIDC_ADMIN_RECOVERY_UNTIL = int(os.environ.get("OIDC_ADMIN_RECOVERY_UNTIL", "0"))
OIDC_ADMIN_RECOVERY_IPS = os.environ.get("OIDC_ADMIN_RECOVERY_IPS", "")
