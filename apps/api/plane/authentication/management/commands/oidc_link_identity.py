# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import logging

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import IntegrityError, transaction

from plane.db.models import OIDCIdentity, User

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Link an independently verified IdP subject to an existing user. Trusted server operators only."

    def add_arguments(self, parser):
        parser.add_argument("--user-id", required=True)
        parser.add_argument("--issuer", required=True)
        parser.add_argument("--subject", required=True)
        parser.add_argument("--confirm-identity-verified", action="store_true")

    @transaction.atomic
    def handle(self, *args, **options):
        if not options["confirm_identity_verified"] or options["issuer"] != settings.OIDC_ISSUER:
            raise CommandError("Independently verify the subject in authentik and use the configured issuer.")
        if not options["subject"] or len(options["subject"]) > 255:
            raise CommandError("Invalid subject")
        try:
            user = User.objects.get(pk=options["user_id"], is_active=True, is_bot=False)
            identity, created = OIDCIdentity.objects.get_or_create(
                issuer=options["issuer"],
                subject=options["subject"],
                defaults={"user": user},
            )
            if identity.user_id != user.id:
                raise CommandError("Identity is already linked; refusing reassignment.")
        except (User.DoesNotExist, ValueError, IntegrityError) as exc:
            raise CommandError("Unable to link identity") from exc
        logger.warning("oidc_identity_linked user_id=%s identity_id=%s created=%s", user.pk, identity.pk, created)
        self.stdout.write(self.style.SUCCESS(f"Identity {identity.pk} linked to user {user.pk}"))
