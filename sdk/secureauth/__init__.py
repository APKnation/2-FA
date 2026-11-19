
"""Python client for the SecureAuth API.

Example
-------
>>> from secureauth import SecureAuthClient
>>> client = SecureAuthClient("http://localhost:8000")
>>> client.register("user@example.com", "Sup3r-Secret!")
>>> login = client.login("user@example.com", "Sup3r-Secret!")
>>> if login["requires_2fa"]:
...     tokens = client.verify_2fa(login["challenge_token"], "123456")
>>> else:
...     tokens = login
>>> client.me()
"""

from __future__ import annotations

import httpx

__version__ = "1.0.0"
__all__ = ["SecureAuthClient", "SecureAuthError"]


class SecureAuthError(Exception):
    """Raised when the API returns an error response."""

    def __init__(self, message: str, status_code: int | None = None, response: httpx.Response | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response


class SecureAuthClient:
    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        *,
        timeout: float = 30.0,
        client: httpx.Client | None = None,
        api_prefix: str = "/api/v1",
    ):
        self.base_url = base_url.rstrip("/")
        self.api_prefix = api_prefix.rstrip("/")
        self._client = client or httpx.Client(base_url=self.base_url, timeout=timeout)
        self.access_token: str | None = None
        self.refresh_token: str | None = None

    # ------------------------------------------------------------------
    # Low-level helpers
    # ------------------------------------------------------------------
    def _request(self, method: str, path: str, *, auto_auth: bool = True, **kwargs) -> dict | None:
        headers = dict(kwargs.pop("headers", None) or {})
        if auto_auth and self.access_token:
            headers.setdefault("Authorization", f"Bearer {self.access_token}")

        response = self._client.request(method, f"{self.api_prefix}{path}", headers=headers, **kwargs)

        if response.status_code >= 400:
            try:
                detail = response.json().get("detail", response.text)
            except ValueError:
                detail = response.text
            raise SecureAuthError(str(detail), status_code=response.status_code, response=response)

        if response.status_code == 204:
            return None
        return response.json()

    def _store_tokens(self, data: dict) -> dict:
        self.access_token = data.get("access_token") or self.access_token
        self.refresh_token = data.get("refresh_token") or self.refresh_token
        return data

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------
    def register(self, email: str, password: str, full_name: str | None = None) -> dict:
        payload = {"email": email, "password": password}
        if full_name is not None:
            payload["full_name"] = full_name
        return self._request("POST", "/auth/register", json=payload, auto_auth=False)

    def login(self, email: str, password: str) -> dict:
        """First factor. Returns tokens, or ``requires_2fa`` + ``challenge_token``."""
        data = self._request(
            "POST",
            "/auth/login",
            json={"email": email, "password": password},
            auto_auth=False,
        )
        if not data.get("requires_2fa"):
            self._store_tokens(data)
        return data

    def login_with_2fa(self, email: str, password: str, code: str) -> dict:
        """Convenience helper that performs both factors in one call."""
        step = self.login(email, password)
        if not step.get("requires_2fa"):
            return step
        data = self.verify_2fa(step["challenge_token"], code)
        self._store_tokens(data)
        return data

    def verify_2fa(self, challenge_token: str, code: str) -> dict:
        return self._request(
            "POST",
            "/auth/verify-2fa",
            json={"challenge_token": challenge_token, "code": code},
            auto_auth=False,
        )

    def refresh(self) -> dict:
        if not self.refresh_token:
            raise SecureAuthError("No refresh token available")
        return self._store_tokens(self._request("POST", "/auth/refresh", json={"refresh_token": self.refresh_token}))

    def logout(self) -> dict:
        data = self._request("POST", "/auth/logout")
        self.access_token = None
        self.refresh_token = None
        return data

    def me(self) -> dict:
        return self._request("GET", "/auth/me")

    def change_password(self, current_password: str, new_password: str) -> dict:
        return self._request(
            "POST",
            "/auth/change-password",
            json={"current_password": current_password, "new_password": new_password},
        )

    # ------------------------------------------------------------------
    # Two-factor authentication management
    # ------------------------------------------------------------------
    def two_factor_setup(self) -> dict:
        return self._request("POST", "/auth/2fa/setup")

    def two_factor_confirm(self, code: str) -> dict:
        return self._request("POST", "/auth/2fa/confirm", json={"code": code})

    def two_factor_status(self) -> dict:
        return self._request("GET", "/auth/2fa/status")

    def two_factor_disable(self, password: str, code: str) -> dict:
        return self._request(
            "POST",
            "/auth/2fa/disable",
            json={"password": password, "code": code},
        )

    def two_factor_regenerate_backup_codes(self, code: str) -> dict:
        return self._request(
            "POST",
            "/auth/2fa/backup-codes/regenerate",
            json={"code": code},
        )

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------
    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "SecureAuthClient":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()
