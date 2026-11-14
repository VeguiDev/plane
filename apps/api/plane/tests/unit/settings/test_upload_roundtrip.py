# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""Real S3-compatible roundtrips in an isolated disposable CI bucket, never production."""

import os
import time
from uuid import uuid4

import pytest
import requests

from plane.settings.storage import S3Storage


@pytest.fixture
def roundtrip_storage(monkeypatch, settings):
    endpoint = os.environ.get("S3_TEST_ENDPOINT")
    if not endpoint:
        pytest.skip("Set S3_TEST_ENDPOINT to an isolated disposable S3 service")
    settings.FILE_SIZE_LIMIT = 1024
    for key, value in {
        "AWS_S3_ENDPOINT_URL": endpoint,
        "USE_MINIO": "0",
        "AWS_REGION": "us-east-1",
        "AWS_ACCESS_KEY_ID": "isolated-storage-test",
        "AWS_SECRET_ACCESS_KEY": "isolated-storage-test-secret",
        "AWS_S3_BUCKET_NAME": f"upload-test-{uuid4().hex}",
    }.items():
        monkeypatch.setenv(key, value)
    storage = S3Storage()
    storage.s3_client.create_bucket(Bucket=storage.aws_storage_bucket_name)
    yield storage
    objects = storage.s3_client.list_objects_v2(Bucket=storage.aws_storage_bucket_name).get("Contents", [])
    for obj in objects:
        storage.s3_client.delete_object(Bucket=storage.aws_storage_bucket_name, Key=obj["Key"])
    storage.s3_client.delete_bucket(Bucket=storage.aws_storage_bucket_name)


@pytest.mark.parametrize("method", ["POST", "PUT"])
def test_roundtrip(roundtrip_storage, method):
    storage = roundtrip_storage
    storage.upload_method = method
    data = storage.generate_presigned_upload("workspace/file.png", "image/png", 12)
    if method == "PUT":
        response = requests.put(data["url"], data=b"x" * 12, headers=data["headers"], timeout=10)
    else:
        response = requests.post(data["url"], data=data["fields"], files={"file": ("file.png", b"x" * 12)}, timeout=10)
    assert response.status_code in (200, 201, 204), response.text
    assert storage.get_object_metadata("workspace/file.png")["ContentLength"] == 12


@pytest.mark.parametrize("body,content_type", [(b"x" * 13, "image/png"), (b"x" * 12, "text/html")])
def test_put_rejects_tampering(roundtrip_storage, body, content_type):
    storage = roundtrip_storage
    storage.upload_method = "PUT"
    data = storage.generate_presigned_upload("workspace/file.png", "image/png", 12)
    response = requests.put(data["url"], data=body, headers={"Content-Type": content_type}, timeout=10)
    assert response.status_code == 403, response.text


def test_put_rejects_changed_key_and_method(roundtrip_storage):
    storage = roundtrip_storage
    storage.upload_method = "PUT"
    data = storage.generate_presigned_upload("workspace/file.png", "image/png", 12)
    response = requests.put(
        data["url"].replace("workspace/file.png", "other/file.png"), data=b"x" * 12, headers=data["headers"], timeout=10
    )
    assert response.status_code == 403
    response = requests.get(data["url"], headers=data["headers"], timeout=10)
    assert response.status_code == 403


def test_put_rejects_expired_signature(roundtrip_storage):
    storage = roundtrip_storage
    storage.upload_method = "PUT"
    data = storage.generate_presigned_upload("workspace/file.png", "image/png", 12, expiration=1)
    time.sleep(2)
    response = requests.put(data["url"], data=b"x" * 12, headers=data["headers"], timeout=10)
    assert response.status_code == 403
