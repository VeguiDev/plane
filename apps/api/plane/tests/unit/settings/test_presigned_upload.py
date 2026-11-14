# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlparse

import pytest
from django.core.exceptions import ImproperlyConfigured
from rest_framework.exceptions import ValidationError

from plane.settings.storage import S3Storage
from plane.utils.asset_upload import merge_asset_attributes, requested_upload_size, validate_uploaded_asset


@pytest.fixture
def storage_env(monkeypatch, settings):
    settings.FILE_SIZE_LIMIT = 1024
    for key, value in {
        "AWS_ACCESS_KEY_ID": "isolated-storage-test",
        "AWS_SECRET_ACCESS_KEY": "isolated-storage-test-secret",
        "AWS_S3_BUCKET_NAME": "test-uploads",
        "AWS_REGION": "auto",
        "AWS_S3_ENDPOINT_URL": "https://account.r2.cloudflarestorage.com",
        "USE_MINIO": "0",
        "S3_UPLOAD_METHOD": "PUT",
        "SIGNED_URL_EXPIRATION": "60",
    }.items():
        monkeypatch.setenv(key, value)


def test_put_signature_binds_type_length_and_exact_key(storage_env):
    result = S3Storage().generate_presigned_upload("workspace/a file.png", "image/png", 12)
    query = parse_qs(urlparse(result["url"]).query)
    assert result["method"] == "PUT"
    assert result["headers"] == {"Content-Type": "image/png"}
    assert query["X-Amz-SignedHeaders"] == ["content-length;content-type;host"]
    assert query["X-Amz-Expires"] == ["60"]
    assert "workspace/a%20file.png" in result["url"]
    assert "/auto/s3/aws4_request" in query["X-Amz-Credential"][0]


def test_post_remains_default_with_range_policy(storage_env, monkeypatch):
    monkeypatch.delenv("S3_UPLOAD_METHOD")
    with patch("plane.settings.storage.boto3.client") as client:
        client.return_value.generate_presigned_post.return_value = {"url": "https://s3.test", "fields": {}}
        result = S3Storage().generate_presigned_upload("key", "image/png", 12)
        assert result["method"] == "POST"
        assert ["content-length-range", 1, 12] in client.return_value.generate_presigned_post.call_args.kwargs[
            "Conditions"
        ]


def test_invalid_method_fails_closed(storage_env, monkeypatch):
    monkeypatch.setenv("S3_UPLOAD_METHOD", "PATCH")
    with pytest.raises(ImproperlyConfigured):
        S3Storage()


@pytest.mark.parametrize("value", [0, -1, 1025, True, None, [], {}, "bad", "1.5", 1.5])
def test_invalid_sizes_rejected(storage_env, value):
    with pytest.raises(ValidationError):
        requested_upload_size(value)


@pytest.mark.parametrize("method", ["POST", "PUT"])
@pytest.mark.parametrize("size", [0, -1, 1025, True, 1.5])
def test_signer_rejects_invalid_size(storage_env, monkeypatch, method, size):
    monkeypatch.setenv("S3_UPLOAD_METHOD", method)
    with pytest.raises(ValidationError):
        S3Storage().generate_presigned_upload("key", "image/png", size)


@pytest.mark.parametrize("size", [1, "1", 1024, "1024"])
def test_valid_size(storage_env, size):
    assert requested_upload_size(size) == int(size)


@pytest.mark.parametrize(
    "metadata",
    [None, {}, {"ContentLength": 13, "ContentType": "image/png"}, {"ContentLength": 12, "ContentType": "text/html"}],
)
def test_put_finalization_rejects_missing_or_changed_object(storage_env, metadata):
    asset = Mock(size=12, attributes={"type": "image/png"}, is_uploaded=False)
    with patch("plane.utils.asset_upload.S3Storage") as storage:
        storage.return_value.get_object_metadata.return_value = metadata
        with pytest.raises(ValidationError):
            validate_uploaded_asset(asset)
    asset.save.assert_not_called()


def test_put_finalization_persists_verified_metadata(storage_env):
    asset = Mock(size=12, attributes={"type": "image/png"}, is_uploaded=False)
    metadata = {"ContentLength": 12, "ContentType": "image/png"}
    with patch("plane.utils.asset_upload.S3Storage") as storage:
        storage.return_value.get_object_metadata.return_value = metadata
        validate_uploaded_asset(asset)
    assert asset.storage_metadata == metadata
    asset.save.assert_called_once_with(update_fields=["storage_metadata"])


def test_post_finalization_unchanged(storage_env, monkeypatch):
    monkeypatch.setenv("S3_UPLOAD_METHOD", "POST")
    with patch("plane.utils.asset_upload.S3Storage") as storage:
        validate_uploaded_asset(Mock(is_uploaded=False))
    storage.assert_not_called()


def test_existing_uploaded_assets_remain_editable_after_cutover(storage_env):
    with patch("plane.utils.asset_upload.S3Storage") as storage:
        validate_uploaded_asset(Mock(is_uploaded=True))
    storage.assert_not_called()


def test_cannot_replace_trusted_type_and_size():
    asset = SimpleNamespace(size=12, attributes={"name": "image.png", "type": "image/png", "size": 12})
    result = merge_asset_attributes(asset, {"type": "text/html", "size": 1, "name": "renamed.png"})
    assert result == {"name": "renamed.png", "type": "image/png", "size": 12}
