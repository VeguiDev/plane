/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { useEffect, useState } from "react";
import { useSearchParams } from "react-router";
import { Button } from "@makeplane/propel/components/button";
import { API_BASE_URL } from "@plane/constants";
import { useTranslation } from "@plane/i18n";
import { AuthService } from "@/services/auth.service";

type LinkStatus = {
  enabled: boolean;
  linked: boolean;
  recent_auth: boolean;
  account_email: string;
  identity_email: string | null;
};

const authService = new AuthService();

export default function SsoLinkPage() {
  const { t } = useTranslation();
  const [search] = useSearchParams();
  const [status, setStatus] = useState<LinkStatus | null>(null);
  const [anonymous, setAnonymous] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const requested = search.get("next_path") || "/";
  // Never navigate to an origin supplied through a login query parameter.
  const nextPath =
    requested.startsWith("/") &&
    !requested.startsWith("//") &&
    !/[\\\r\n]/.test(requested) &&
    !requested.startsWith("/sso-link")
      ? requested
      : "/";
  const returnPath = `/sso-link?${new URLSearchParams({ next_path: nextPath })}`;
  const loginPath = `/?${new URLSearchParams({ next_path: returnPath })}`;

  useEffect(() => {
    const controller = new AbortController();
    fetch(`${API_BASE_URL}/auth/oidc/link/`, { credentials: "include", cache: "no-store", signal: controller.signal })
      .then(async (response) => {
        if (response.status === 401) {
          setAnonymous(true);
          return null;
        }
        if (!response.ok) throw new Error("link_status_failed");
        setStatus((await response.json()) as LinkStatus);
        return null;
      })
      .catch(() => {
        if (!controller.signal.aborted) setError(true);
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoaded(true);
      });
    return () => controller.abort();
  }, []);

  const post = async (path: string) => {
    const token = (await authService.requestCSRFToken()).csrf_token;
    if (!token) throw new Error("csrf_unavailable");
    return fetch(`${API_BASE_URL}${path}`, {
      method: "POST",
      credentials: "include",
      headers: { "X-CSRFToken": token },
    });
  };

  const act = async (action: "start" | "confirm" | "cancel" | "reauthenticate") => {
    setBusy(true);
    setError(false);
    try {
      if (action === "start") {
        const token = (await authService.requestCSRFToken()).csrf_token;
        if (!token) throw new Error("csrf_unavailable");
        // A normal form navigation follows the IdP redirect without fetching it via CORS.
        const form = document.createElement("form");
        form.method = "POST";
        form.action = `${API_BASE_URL}/auth/oidc/link/`;
        for (const [name, value] of Object.entries({ csrfmiddlewaretoken: token, next_path: nextPath })) {
          const input = document.createElement("input");
          input.type = "hidden";
          input.name = name;
          input.value = value;
          form.appendChild(input);
        }
        document.body.appendChild(form);
        form.submit();
        return;
      }
      if (action === "reauthenticate") {
        const response = await post("/auth/sign-out/");
        if (!response.ok) throw new Error("sign_out_failed");
        window.location.assign(loginPath);
        return;
      }
      const response = await post(`/auth/oidc/link/${action}/`);
      if (!response.ok) throw new Error("link_action_failed");
      if (action === "confirm") setStatus((current) => current && { ...current, linked: true, identity_email: null });
      else window.location.replace(returnPath);
    } catch {
      setError(true);
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="mx-auto flex min-h-screen max-w-xl flex-col justify-center gap-5 p-6">
      <h1 className="text-h4-semibold">{t("oidc_link.title")}</h1>
      <p>{t("oidc_link.description")}</p>
      {search.get("reason") && (
        <p role="status">
          {t(search.get("reason") === "account_link_required" ? "oidc_link.login_required" : "oidc_link.retry")}
        </p>
      )}
      {error && <p role="alert">{t("oidc_link.error")}</p>}
      {!loaded && <p role="status">{t("oidc_link.loading")}</p>}
      {anonymous && (
        <a className="underline" href={loginPath}>
          {t("oidc_link.sign_in")}
        </a>
      )}
      {status && !status.enabled && <p>{t("oidc_link.disabled")}</p>}
      {status?.enabled && status.linked && (
        <>
          <p role="status">{t("oidc_link.linked")}</p>
          <a className="underline" href={nextPath}>
            {t("oidc_link.continue")}
          </a>
        </>
      )}
      {status?.enabled && !status.linked && (
        <>
          <p>
            {t("oidc_link.local_account")}: <strong>{status.account_email}</strong>
          </p>
          {!status.recent_auth ? (
            <>
              <p>{t("oidc_link.reauthenticate")}</p>
              <Button
                variant="primary"
                size="lg"
                stretch="auto"
                onClick={() => void act("reauthenticate")}
                disabled={busy}
                label={t("oidc_link.sign_in_again")}
              />
            </>
          ) : status.identity_email ? (
            <>
              <p>
                {t("oidc_link.sso_identity")}: <strong>{status.identity_email}</strong>
              </p>
              <p>{t("oidc_link.confirm_description")}</p>
              <Button
                variant="primary"
                size="lg"
                stretch="auto"
                onClick={() => void act("confirm")}
                disabled={busy}
                label={t("oidc_link.confirm")}
              />
              <Button
                variant="secondary"
                size="lg"
                stretch="auto"
                onClick={() => void act("cancel")}
                disabled={busy}
                label={t("oidc_link.cancel")}
              />
            </>
          ) : (
            <Button
              variant="primary"
              size="lg"
              stretch="auto"
              onClick={() => void act("start")}
              disabled={busy}
              label={t("oidc_link.link")}
            />
          )}
        </>
      )}
    </main>
  );
}
