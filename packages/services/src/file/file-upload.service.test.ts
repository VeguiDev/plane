/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import axios, { CanceledError } from "axios";
import { afterEach, describe, expect, it, vi } from "vitest";
import { FileUploadService } from "./file-upload.service";
import { generateFileUploadPayload } from "./helper";
import type { TFileSignedURLResponse } from "@plane/types";

afterEach(() => vi.restoreAllMocks());

describe("signed uploads", () => {
  const file = new File(["hello"], "file.png", { type: "image/png" });
  const url = "https://storage.test/key?X-Amz-Signature=untouched";

  it("sends PUT as exact binary with signed headers and no cookies", async () => {
    const request = vi.spyOn(axios, "request").mockResolvedValue({ data: "" });
    const response: TFileSignedURLResponse = {
      asset_id: "id",
      asset_url: "/asset",
      upload_data: { method: "PUT", url, headers: { "Content-Type": "image/png" } },
    };
    const body = generateFileUploadPayload(response, file);
    expect(body).toBe(file);
    const progress = vi.fn();
    await new FileUploadService().uploadFile(response.upload_data, body, progress);
    expect(request).toHaveBeenCalledWith(
      expect.objectContaining({
        url,
        method: "PUT",
        data: file,
        headers: { "Content-Type": "image/png" },
        withCredentials: false,
        onUploadProgress: progress,
      })
    );
  });

  it.each([undefined, "POST"] as const)("keeps legacy POST method %s with all fields", async (method) => {
    const request = vi.spyOn(axios, "request").mockResolvedValue({ data: "" });
    const response: TFileSignedURLResponse = {
      asset_id: "id",
      asset_url: "/asset",
      upload_data: { method, url, fields: { policy: "policy", key: "key" } },
    };
    const body = generateFileUploadPayload(response, file) as FormData;
    expect(body.get("policy")).toBe("policy");
    expect(body.get("file")).toBeInstanceOf(File);
    await new FileUploadService().uploadFile(response.upload_data, body);
    expect(request).toHaveBeenCalledWith(
      expect.objectContaining({ method: "POST", data: body, withCredentials: false })
    );
  });

  it("rejects cancellation instead of treating it as a successful upload", async () => {
    vi.spyOn(axios, "request").mockRejectedValue(new CanceledError("cancelled"));
    await expect(new FileUploadService().uploadFile({ method: "PUT", url, headers: {} }, file)).rejects.toThrow(
      "cancelled"
    );
  });

  it("propagates storage failures", async () => {
    vi.spyOn(axios, "request").mockRejectedValue({ response: { data: "SignatureDoesNotMatch" } });
    await expect(new FileUploadService().uploadFile({ method: "PUT", url, headers: {} }, file)).rejects.toBe(
      "SignatureDoesNotMatch"
    );
  });
});
