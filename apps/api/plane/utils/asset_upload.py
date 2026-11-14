# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import os

from django.conf import settings
from rest_framework.exceptions import ValidationError

from plane.settings.storage import S3Storage


def requested_upload_size(value):
    """Reject invalid declarations rather than silently signing a different size."""
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValidationError({"size": "Invalid file size."})
    try:
        size = int(value)
    except (TypeError, ValueError, OverflowError):
        raise ValidationError({"size": "Invalid file size."})
    if not 1 <= size <= settings.FILE_SIZE_LIMIT:
        raise ValidationError({"size": "File size must be within the instance upload limit."})
    return size


def validate_uploaded_asset(asset):
    """PUT has no POST range policy. Never finalize an absent/mismatched object."""
    if asset.is_uploaded or os.environ.get("S3_UPLOAD_METHOD", "POST").upper() != "PUT":
        return
    metadata = S3Storage().get_object_metadata(asset.asset.name)
    if (
        not metadata
        or metadata.get("ContentLength") != asset.size
        or not 1 <= metadata["ContentLength"] <= settings.FILE_SIZE_LIMIT
        or metadata.get("ContentType") != asset.attributes.get("type")
    ):
        raise ValidationError({"upload": "Uploaded object is missing or its size/content type does not match."})
    asset.storage_metadata = metadata
    asset.save(update_fields=["storage_metadata"])


def merge_asset_attributes(asset, attributes):
    """Client-editable names must not replace the upload's trusted size/type."""
    if attributes is None:
        return asset.attributes
    if not isinstance(attributes, dict):
        raise ValidationError({"attributes": "Expected an object."})
    return {**asset.attributes, **attributes, "size": asset.size, "type": asset.attributes.get("type")}
