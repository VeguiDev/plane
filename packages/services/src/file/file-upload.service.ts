/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import axios, { CancelToken, isCancel } from "axios";
import type { AxiosRequestConfig, CancelTokenSource } from "axios";
import type { TFileUploadData } from "@plane/types";
// api service
import { APIService } from "../api.service";

/**
 * Service class for handling file upload operations
 * Handles file uploads
 * @extends {APIService}
 */
export class FileUploadService extends APIService {
  private cancelSource?: CancelTokenSource;

  constructor() {
    super("");
  }

  /**
   * Uploads a file to the specified signed URL
   * @param {TFileUploadData} upload - Signed method, URL and fields/headers
   * @param {FormData | File} data - Multipart POST or binary PUT body
   * @returns {Promise<void>} Promise resolving to void
   * @throws {Error} If the request fails
   */
  async uploadFile(
    upload: TFileUploadData,
    data: FormData | File,
    onUploadProgress?: AxiosRequestConfig["onUploadProgress"]
  ): Promise<void> {
    this.cancelSource = CancelToken.source();
    // Do not run signed URLs through API URL normalization or attach Plane cookies.
    return axios
      .request({
        url: upload.url,
        method: upload.method ?? "POST",
        data,
        headers: upload.method === "PUT" ? upload.headers : { "Content-Type": "multipart/form-data" },
        cancelToken: this.cancelSource.token,
        withCredentials: false,
        onUploadProgress,
      })
      .then(() => undefined)
      .catch((error) => {
        if (isCancel(error)) {
          throw error;
        }
        throw error?.response?.data ?? error;
      });
  }

  /**
   * Cancels the upload
   */
  cancelUpload() {
    this.cancelSource?.cancel("Upload canceled");
  }
}
