# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from unittest.mock import patch

import pytest
from rest_framework.test import APIClient

from plane.db.models import FileAsset, User
from plane.tests.factories import UserFactory, WorkspaceMemberFactory


@pytest.mark.django_db
@pytest.mark.parametrize("method", ["POST", "PUT"])
def test_user_upload_contract_and_permissions(create_user, monkeypatch, settings, method):
    monkeypatch.setenv("S3_UPLOAD_METHOD", method)
    settings.FILE_SIZE_LIMIT = 1024
    client = APIClient()
    client.force_authenticate(create_user)
    descriptor = {"method": method, "url": "https://storage.test/upload"}
    descriptor["headers" if method == "PUT" else "fields"] = {"Content-Type": "image/png"}
    with patch("plane.app.views.asset.v2.S3Storage") as signer:
        signer.return_value.generate_presigned_upload.return_value = descriptor
        response = client.post(
            "/api/assets/v2/user-assets/",
            {
                "name": "avatar.png",
                "size": 12,
                "type": "image/png",
                "entity_type": "USER_AVATAR",
            },
            format="json",
        )
    assert response.status_code == 200, response.data
    assert response.data["upload_data"] == descriptor
    asset_id = response.data["asset_id"]
    asset = FileAsset.objects.get(id=asset_id)
    assert not asset.is_uploaded
    other = User.objects.create(email="other-upload@example.test", username="other-upload")
    client.force_authenticate(other)
    with patch("plane.utils.asset_upload.S3Storage") as metadata:
        response = client.patch(f"/api/assets/v2/user-assets/{asset_id}/", {}, format="json")
        assert response.status_code in (403, 404)
        metadata.assert_not_called()


@pytest.mark.django_db
@pytest.mark.parametrize(
    "metadata,expected",
    [
        (None, 400),
        ({"ContentLength": 13, "ContentType": "image/png"}, 400),
        ({"ContentLength": 12, "ContentType": "text/html"}, 400),
        ({"ContentLength": 12, "ContentType": "image/png"}, 204),
    ],
)
def test_put_confirmation_fails_closed(create_user, monkeypatch, settings, metadata, expected):
    monkeypatch.setenv("S3_UPLOAD_METHOD", "PUT")
    settings.FILE_SIZE_LIMIT = 1024
    asset = FileAsset.objects.create(
        asset="avatar.png",
        user=create_user,
        size=12,
        attributes={"type": "image/png", "size": 12},
        entity_type="USER_AVATAR",
    )
    client = APIClient()
    client.force_authenticate(create_user)
    with patch("plane.utils.asset_upload.S3Storage") as storage:
        storage.return_value.get_object_metadata.return_value = metadata
        response = client.patch(f"/api/assets/v2/user-assets/{asset.id}/", {}, format="json")
    assert response.status_code == expected, getattr(response, "data", None)
    asset.refresh_from_db()
    assert asset.is_uploaded == (expected == 204)


@pytest.mark.django_db
@pytest.mark.parametrize("method", ["POST", "PUT"])
@pytest.mark.parametrize("role", [5, 15, 20])
def test_workspace_logo_permissions_unchanged(workspace, monkeypatch, method, role, mock_celery):
    monkeypatch.setenv("S3_UPLOAD_METHOD", method)
    caller = UserFactory()
    WorkspaceMemberFactory(workspace=workspace, member=caller, role=role)
    asset = FileAsset.objects.create(
        asset=f"{workspace.id}/logo.png",
        workspace=workspace,
        size=12,
        attributes={"type": "image/png", "size": 12},
        entity_type="WORKSPACE_LOGO",
    )
    client = APIClient()
    client.force_authenticate(caller)
    with patch("plane.utils.asset_upload.S3Storage") as storage:
        storage.return_value.get_object_metadata.return_value = {"ContentLength": 12, "ContentType": "image/png"}
        response = client.patch(f"/api/assets/v2/workspaces/{workspace.slug}/{asset.id}/", {}, format="json")
        assert response.status_code == (204 if role == 20 else 403), getattr(response, "data", None)
        if role != 20:
            storage.assert_not_called()
    asset.refresh_from_db()
    assert asset.is_uploaded == (role == 20)


@pytest.mark.django_db
def test_put_cannot_confirm_asset_outside_workspace(workspace, monkeypatch):
    monkeypatch.setenv("S3_UPLOAD_METHOD", "PUT")
    caller = UserFactory()
    asset = FileAsset.objects.create(
        asset=f"{workspace.id}/logo.png",
        workspace=workspace,
        size=12,
        attributes={"type": "image/png", "size": 12},
        entity_type="WORKSPACE_LOGO",
    )
    client = APIClient()
    client.force_authenticate(caller)
    with patch("plane.utils.asset_upload.S3Storage") as storage:
        response = client.patch(f"/api/assets/v2/workspaces/{workspace.slug}/{asset.id}/", {}, format="json")
        assert response.status_code in (403, 404)
        storage.assert_not_called()
    asset.refresh_from_db()
    assert not asset.is_uploaded
