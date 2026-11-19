
import pyotp

EMAIL = "bob@example.com"
PASSWORD = "Sup3r-Secret!"


def register(client, email=EMAIL, password=PASSWORD):
    return client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password, "full_name": "Bob"},
    )


def login(client, email=EMAIL, password=PASSWORD):
    return client.post("/api/v1/auth/login", json={"email": email, "password": password})


def headers(token):
    return {"Authorization": f"Bearer {token}"}


def enable_2fa(client):
    """Register a user, enrol 2FA and return (access_token, secret, backup_codes)."""
    register(client)
    access = login(client).json()["access_token"]
    auth = headers(access)

    setup = client.post("/api/v1/auth/2fa/setup", headers=auth)
    assert setup.status_code == 200
    secret = setup.json()["secret"]

    code = pyotp.TOTP(secret).now()
    confirm = client.post("/api/v1/auth/2fa/confirm", json={"code": code}, headers=auth)
    assert confirm.status_code == 200
    return access, secret, confirm.json()["codes"]


def test_setup_returns_secret_and_qrcode(client):
    register(client)
    access = login(client).json()["access_token"]

    response = client.post("/api/v1/auth/2fa/setup", headers=headers(access))
    assert response.status_code == 200
    body = response.json()
    assert body["secret"]
    assert body["provisioning_uri"].startswith("otpauth://totp/")
    assert body["qrcode"].startswith("data:image/svg+xml;base64,")

    # Setup alone must not enable 2FA.
    status = client.get("/api/v1/auth/2fa/status", headers=headers(access))
    assert status.json()["enabled"] is False


def test_confirm_enables_2fa_and_issues_backup_codes(client):
    access, secret, codes = enable_2fa(client)
    assert len(codes) == 10

    status = client.get("/api/v1/auth/2fa/status", headers=headers(access))
    assert status.json() == {"enabled": True, "backup_codes_remaining": 10}


def test_confirm_rejects_wrong_code(client):
    register(client)
    access = login(client).json()["access_token"]
    client.post("/api/v1/auth/2fa/setup", headers=headers(access))

    response = client.post("/api/v1/auth/2fa/confirm", json={"code": "000000"}, headers=headers(access))
    assert response.status_code == 400


def test_login_requires_second_factor(client):
    enable_2fa(client)
    response = login(client)
    assert response.status_code == 200
    body = response.json()
    assert body["requires_2fa"] is True
    assert body["access_token"] is None
    assert body["challenge_token"]


def test_verify_challenge_with_totp(client):
    register(client, email="totp@example.com")
    access = login(client, email="totp@example.com").json()["access_token"]
    auth = headers(access)
    secret = client.post("/api/v1/auth/2fa/setup", headers=auth).json()["secret"]
    client.post(
        "/api/v1/auth/2fa/confirm",
        json={"code": pyotp.TOTP(secret).now()},
        headers=auth,
    )

    challenge = login(client, email="totp@example.com").json()["challenge_token"]
    response = client.post(
        "/api/v1/auth/verify-2fa",
        json={"challenge_token": challenge, "code": pyotp.TOTP(secret).now()},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["access_token"]
    assert body["refresh_token"]


def test_verify_challenge_rejects_wrong_code(client):
    register(client, email="wrong@example.com")
    access = login(client, email="wrong@example.com").json()["access_token"]
    auth = headers(access)
    secret = client.post("/api/v1/auth/2fa/setup", headers=auth).json()["secret"]
    client.post(
        "/api/v1/auth/2fa/confirm",
        json={"code": pyotp.TOTP(secret).now()},
        headers=auth,
    )

    challenge = login(client, email="wrong@example.com").json()["challenge_token"]
    response = client.post(
        "/api/v1/auth/verify-2fa",
        json={"challenge_token": challenge, "code": "000000"},
    )
    assert response.status_code == 401


def test_backup_code_can_finish_login_and_is_single_use(client):
    register(client, email="backup@example.com")
    access = login(client, email="backup@example.com").json()["access_token"]
    auth = headers(access)
    secret = client.post("/api/v1/auth/2fa/setup", headers=auth).json()["secret"]
    codes = client.post(
        "/api/v1/auth/2fa/confirm",
        json={"code": pyotp.TOTP(secret).now()},
        headers=auth,
    ).json()["codes"]

    challenge = login(client, email="backup@example.com").json()["challenge_token"]
    first = client.post(
        "/api/v1/auth/verify-2fa",
        json={"challenge_token": challenge, "code": codes[0]},
    )
    assert first.status_code == 200

    challenge = login(client, email="backup@example.com").json()["challenge_token"]
    second = client.post(
        "/api/v1/auth/verify-2fa",
        json={"challenge_token": challenge, "code": codes[0]},
    )
    assert second.status_code == 401

    status = client.get("/api/v1/auth/2fa/status", headers=auth)
    assert status.json()["backup_codes_remaining"] == 9


def test_regenerate_backup_codes_invalidates_old_ones(client):
    register(client, email="regen@example.com")
    access = login(client, email="regen@example.com").json()["access_token"]
    auth = headers(access)
    secret = client.post("/api/v1/auth/2fa/setup", headers=auth).json()["secret"]
    old_codes = client.post(
        "/api/v1/auth/2fa/confirm",
        json={"code": pyotp.TOTP(secret).now()},
        headers=auth,
    ).json()["codes"]

    response = client.post(
        "/api/v1/auth/2fa/backup-codes/regenerate",
        json={"code": pyotp.TOTP(secret).now()},
        headers=auth,
    )
    assert response.status_code == 200
    new_codes = response.json()["codes"]
    assert set(new_codes).isdisjoint(old_codes)


def test_disable_requires_password_and_code(client):
    register(client, email="disable@example.com")
    access = login(client, email="disable@example.com").json()["access_token"]
    auth = headers(access)
    secret = client.post("/api/v1/auth/2fa/setup", headers=auth).json()["secret"]
    client.post(
        "/api/v1/auth/2fa/confirm",
        json={"code": pyotp.TOTP(secret).now()},
        headers=auth,
    )

    wrong_password = client.post(
        "/api/v1/auth/2fa/disable",
        json={"password": "nope", "code": pyotp.TOTP(secret).now()},
        headers=auth,
    )
    assert wrong_password.status_code == 400

    ok = client.post(
        "/api/v1/auth/2fa/disable",
        json={"password": PASSWORD, "code": pyotp.TOTP(secret).now()},
        headers=auth,
    )
    assert ok.status_code == 200
    assert client.get("/api/v1/auth/2fa/status", headers=auth).json()["enabled"] is False


def test_endpoints_require_authentication(client):
    assert client.post("/api/v1/auth/2fa/setup").status_code == 401
    assert client.get("/api/v1/auth/2fa/status").status_code == 401
    assert client.post("/api/v1/auth/2fa/confirm", json={"code": "123456"}).status_code == 401
    assert client.post("/api/v1/auth/logout").status_code == 401
