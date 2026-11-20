
EMAIL = "alice@example.com"
PASSWORD = "Sup3r-Secret!"

import app.services.auth_service as auth_service

# Make email OTP deterministic in tests.
auth_service._generate_email_otp = lambda: "123456"
auth_service.mail.send_verification_code = lambda *a, **k: True


def register(client, email=EMAIL, password=PASSWORD, full_name="Alice"):
    return client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password, "full_name": full_name},
    )def login(client, email=EMAIL, password=PASSWORD):
    response = client.post(
        "/api/v1/auth/login", json={"email": email, "password": password}
    )
    if response.status_code == 200 and response.json().get("requires_2fa"):
        challenge = response.json()["challenge_token"]
        return client.post(
            "/api/v1/auth/verify-2fa",
            json={"challenge_token": challenge, "code": "123456"},
        )
    return response


def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_register_success(client):
    response = register(client)
    assert response.status_code == 201
    body = response.json()
    assert body["email"] == EMAIL
    assert body["full_name"] == "Alice"
    assert body["is_active"] is True
    assert body["totp_enabled"] is False
    assert "password" not in body
    assert "hashed_password" not in body


def test_register_duplicate(client):
    assert register(client).status_code == 201
    response = register(client)
    assert response.status_code == 409


def test_register_rejects_short_password(client):
    response = register(client, email="short@example.com", password="short")
    assert response.status_code == 422


def test_login_success(client):
    register(client)
    response = login(client)
    assert response.status_code == 200
    body = response.json()
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["token_type"] == "bearer"
    assert body["expires_in"] > 0


def test_login_wrong_password(client):
    register(client)
    response = login(client, password="wrong-password")
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect email or password"


def test_login_unknown_user(client):
    response = login(client, email="nobody@example.com")
    assert response.status_code == 401


def test_login_lockout_after_failed_attempts(client):
    register(client, email="lock@example.com")
    for _ in range(5):
        assert login(client, email="lock@example.com", password="nope").status_code == 401

    response = login(client, email="lock@example.com", password=PASSWORD)
    assert response.status_code == 423


def test_me_requires_authentication(client):
    assert client.get("/api/v1/auth/me").status_code == 401


def test_me(client):
    register(client)
    token = login(client).json()["access_token"]
    response = client.get("/api/v1/auth/me", headers=auth_headers(token))
    assert response.status_code == 200
    assert response.json()["email"] == EMAIL


def test_me_rejects_invalid_token(client):
    response = client.get("/api/v1/auth/me", headers=auth_headers("not-a-token"))
    assert response.status_code == 401


def test_refresh(client):
    register(client)
    refresh_token = login(client).json()["refresh_token"]

    response = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert response.status_code == 200
    body = response.json()
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["refresh_token"] != refresh_token


def test_refresh_rejects_access_token(client):
    register(client)
    access_token = login(client).json()["access_token"]
    response = client.post("/api/v1/auth/refresh", json={"refresh_token": access_token})
    assert response.status_code == 401


def test_logout_invalidates_refresh_token(client):
    register(client)
    body = login(client).json()

    assert client.post("/api/v1/auth/logout", headers=auth_headers(body["access_token"])).status_code == 200

    response = client.post("/api/v1/auth/refresh", json={"refresh_token": body["refresh_token"]})
    assert response.status_code == 401


def test_change_password(client):
    register(client)
    body = login(client).json()
    headers = auth_headers(body["access_token"])

    response = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": PASSWORD, "new_password": "N3w-Secret!"},
        headers=headers,
    )
    assert response.status_code == 200

    assert login(client, password=PASSWORD).status_code == 401
    assert login(client, password="N3w-Secret!").status_code == 200


def test_change_password_wrong_current(client):
    register(client)
    headers = auth_headers(login(client).json()["access_token"])
    response = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "wrong", "new_password": "N3w-Secret!"},
        headers=headers,
    )
    assert response.status_code == 400


def test_change_password_rejects_reuse(client):
    register(client)
    headers = auth_headers(login(client).json()["access_token"])
    response = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": PASSWORD, "new_password": PASSWORD},
        headers=headers,
    )
    assert response.status_code == 400
