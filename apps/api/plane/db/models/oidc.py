# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import uuid

from django.conf import settings
from django.db import models


class OIDCIdentity(models.Model):
    """Stable federated identity. Email is deliberately NOT its key."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    issuer = models.CharField(max_length=512)
    subject = models.CharField(max_length=255)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="oidc_identities")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "oidc_identities"
        constraints = [models.UniqueConstraint(fields=["issuer", "subject"], name="oidc_issuer_subject_unique")]


class OIDCLoginTransaction(models.Model):
    """Short-lived, server-side, atomically consumed authorization transactions."""

    state_hash = models.CharField(primary_key=True, max_length=64)
    session_hash = models.CharField(max_length=64)
    nonce = models.CharField(max_length=128)
    verifier = models.CharField(max_length=128)
    redirect_uri = models.URLField(max_length=1024)
    next_path = models.CharField(max_length=500, default="")
    target = models.CharField(max_length=10, default="app")
    expires_at = models.DateTimeField(db_index=True)

    class Meta:
        db_table = "oidc_login_transactions"
