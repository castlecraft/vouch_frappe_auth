import base64
import datetime
import gzip
import os

import frappe
import jwt
import pytest

from vouch_frappe_auth.auth import (  # isort: skip
    extract_token,
    get_vouch_config,
    resolve_email_from_payload,
    validate_vouch_jwt,
)

SAMPLE_VOUCH_SECRET = "vouch_jwt_secret_32_bytes_frappe_auth!!"


@pytest.fixture(scope="module")
def frappe_site_context():
    """Initializes Frappe context with the test/development site."""
    original_cwd = os.getcwd()
    if not getattr(frappe, "db", None) or not frappe.db:
        site_name = os.getenv("FRAPPE_SITE", "development.localhost")
        sites_path = os.getenv("FRAPPE_SITES_PATH")
        if not sites_path:
            candidates = [
                os.path.abspath(
                    os.path.join(os.path.dirname(__file__), "../../../sites")
                ),
                "/workspace/frappe-bench/sites",
                os.path.abspath("./sites"),
                os.path.abspath("../sites"),
            ]
            for candidate in candidates:
                if os.path.exists(candidate):
                    sites_path = os.path.abspath(candidate)
                    break

        if sites_path and os.path.exists(sites_path):
            os.chdir(sites_path)
            logs_dir = os.path.abspath(os.path.join(sites_path, "..", "logs"))
            os.makedirs(logs_dir, exist_ok=True)
            frappe.init(site=site_name, sites_path=sites_path)
        else:
            frappe.init(site=site_name)

        frappe.connect()
    yield
    if getattr(frappe, "db", None) and frappe.db:
        frappe.db.rollback()
    try:
        os.chdir(original_cwd)
    except Exception:
        pass


@pytest.fixture(autouse=True)
def clean_request_context():
    """Ensures clean request and session context for every test."""
    original_session = getattr(frappe, "session", None)
    original_request = getattr(frappe, "request", None)
    original_local_session = getattr(getattr(frappe, "local", None), "session", None)
    original_login_manager = getattr(
        getattr(frappe, "local", None), "login_manager", None
    )

    frappe.session = frappe._dict(user="Guest", data=frappe._dict(user="Guest"))
    if hasattr(frappe, "local"):
        frappe.local.session = frappe.session
        frappe.local.login_manager = frappe._dict(user="Guest")

    yield

    frappe.session = original_session
    frappe.request = original_request
    if hasattr(frappe, "local"):
        frappe.local.session = original_local_session
        frappe.local.login_manager = original_login_manager


def _create_vouch_cookie(
    username: str, email: str, secret: str = SAMPLE_VOUCH_SECRET
) -> str:
    exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=30)
    payload = {
        "iss": "Vouch Proxy",
        "username": username,
        "CustomClaims": {
            "email": email,
            "username": username,
            "groups": ["developers"],
            "name": username.capitalize(),
        },
        "exp": int(exp.timestamp()),
        "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()),
    }
    raw_jwt = jwt.encode(payload, secret, algorithm="HS256")
    compressed = gzip.compress(raw_jwt.encode("utf-8"))
    return base64.urlsafe_b64encode(compressed).decode("utf-8")


def test_e2e_site_config_loaded(frappe_site_context):
    config = get_vouch_config()
    assert config["enabled"] in (True, 1)
    assert config["jwt_secret"] == SAMPLE_VOUCH_SECRET
    assert config["algorithms"] == ["HS256"]


def test_e2e_auth_hooks_registered(frappe_site_context):
    hooks = frappe.get_hooks("auth_hooks")
    assert "vouch_frappe_auth.auth.validate_vouch_jwt" in hooks


def test_e2e_vouch_cookie_decompression_and_jwt_verification(frappe_site_context):
    username = "developer"
    email = "developer@example.org"
    cookie_val = _create_vouch_cookie(username, email)

    clean_cookie = cookie_val.strip()
    clean_cookie += "=" * (-len(clean_cookie) % 4)
    compressed = base64.urlsafe_b64decode(clean_cookie)
    decompressed_jwt = gzip.decompress(compressed).decode("utf-8")

    config = get_vouch_config()
    payload = jwt.decode(
        decompressed_jwt,
        key=config["jwt_secret"],
        algorithms=config["algorithms"],
        options={"verify_aud": False},
    )

    assert payload["iss"] == "Vouch Proxy"
    assert payload["username"] == username
    assert payload["CustomClaims"]["email"] == email

    resolved_email = resolve_email_from_payload(payload, config["email_claim"])
    assert resolved_email in (username, email)


def test_e2e_validate_vouch_jwt_via_cookie(frappe_site_context):
    user_email = "e2e_cookie_user@example.org"
    cookie_val = _create_vouch_cookie(user_email, user_email)

    class MockRequest:
        cookies = {"VouchCookie": cookie_val}
        headers = {
            "Cookie": f"VouchCookie={cookie_val}",
            "cookie": f"VouchCookie={cookie_val}",
        }
        host = "development.localhost"

    frappe.request = MockRequest()

    config = get_vouch_config()
    token = extract_token(config)
    assert token is not None

    validate_vouch_jwt()

    assert frappe.session.user == user_email
    assert frappe.local.session.user == user_email


def test_e2e_validate_vouch_jwt_via_header(frappe_site_context):
    user_email = "e2e_header_user@example.org"
    exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=30)
    raw_jwt = jwt.encode(
        {"username": user_email, "email": user_email, "exp": int(exp.timestamp())},
        SAMPLE_VOUCH_SECRET,
        algorithm="HS256",
    )

    class MockRequest:
        cookies = {}
        headers = {"X-Vouch-Token": raw_jwt, "x-vouch-token": raw_jwt}
        host = "development.localhost"

    frappe.request = MockRequest()

    config = get_vouch_config()
    token = extract_token(config)
    assert token == raw_jwt

    validate_vouch_jwt()

    assert frappe.session.user == user_email


def test_e2e_invalid_secret_rejected(frappe_site_context):
    cookie_val = _create_vouch_cookie(
        "attacker", "attacker@example.org", secret="wrong_secret_12345678901234567890!!"
    )

    class MockRequest:
        cookies = {"VouchCookie": cookie_val}
        headers = {"Cookie": f"VouchCookie={cookie_val}"}
        host = "development.localhost"

    frappe.request = MockRequest()

    validate_vouch_jwt()

    assert frappe.session.user == "Guest"
