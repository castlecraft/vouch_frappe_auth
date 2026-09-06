import datetime
import sys
from unittest.mock import MagicMock

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

# --- 1. Mock Frappe module before importing auth ---
frappe_mock = MagicMock()
frappe_mock.local = MagicMock()
frappe_mock.local.form_dict = {}

sys.modules["frappe"] = frappe_mock

from vouch_frappe_auth.auth import extract_token  # noqa: E402
from vouch_frappe_auth.auth import validate_vouch_jwt  # noqa: E402


def _to_bool(val, default=False) -> bool:
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    return str(val).strip().lower() in ("1", "true", "yes", "on")


TEST_HMAC_SECRET = "super_secret_vouch_jwt_signing_key_32_bytes!!"


# --- 2. Pytest Fixtures ---
@pytest.fixture(autouse=True)
def reset_frappe_state():
    frappe_mock.reset_mock()

    config_store = {}
    frappe_mock.conf = config_store
    frappe_mock.get_conf.return_value = config_store
    frappe_mock.local.form_dict = {}

    # Strict in-memory cache mock (default get_value to None, not a MagicMock)
    cache_store = {}
    cache_mock = MagicMock()
    cache_mock.get_value.side_effect = lambda k: cache_store.get(k, None)
    cache_mock.set_value.side_effect = lambda k, v, **kw: cache_store.update({k: v})
    cache_mock.delete_key.side_effect = lambda k: cache_store.pop(k, None)
    frappe_mock.cache.return_value = cache_mock

    frappe_mock.log_error.side_effect = lambda title="", message="": None
    yield


@pytest.fixture
def rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": "test-kid-123",
                "n": jwt.utils.base64url_encode(
                    public_key.public_numbers().n.to_bytes(256, "big")
                ).decode("utf-8"),
                "e": jwt.utils.base64url_encode(
                    public_key.public_numbers().e.to_bytes(3, "big")
                ).decode("utf-8"),
                "alg": "RS256",
            }
        ]
    }
    return private_key, jwks


def set_frappe_config(conf_dict: dict):
    frappe_mock.conf.clear()
    frappe_mock.conf.update(conf_dict)
    frappe_mock.get_conf.return_value = frappe_mock.conf


# --- 3. Unit Tests: Utilities ---
@pytest.mark.parametrize(
    "input_val, expected",
    [
        (True, True),
        ("true", True),
        ("1", True),
        ("yes", True),
        (False, False),
        ("false", False),
        ("0", False),
        (None, False),
    ],
)
def test_to_bool(input_val, expected):
    assert _to_bool(input_val) == expected


@pytest.mark.parametrize(
    "header_name, prefix, incoming_header, expected_token",
    [
        ("Authorization", "Bearer", "Bearer my_jwt_token", "my_jwt_token"),
        ("Authorization", "Bearer", "bearer my_jwt_token", "my_jwt_token"),
        ("X-Vouch-Token", "", "raw_jwt_token", "raw_jwt_token"),
        ("Authorization", "Bearer", "Basic credentials", None),
        ("Authorization", "Bearer", "", None),
    ],
)
def test_extract_token(header_name, prefix, incoming_header, expected_token):
    frappe_mock.get_request_header.return_value = incoming_header
    config = {"header_name": header_name, "header_prefix": prefix}
    assert extract_token(config) == expected_token


# --- 4. Functional Tests ---
def test_validate_vouch_jwt_disabled():
    set_frappe_config({"vouch_jwt_enabled": False})
    frappe_mock.get_request_header.return_value = "Bearer test-token"

    validate_vouch_jwt()
    frappe_mock.set_user.assert_not_called()


def test_validate_vouch_jwt_hs256_success():
    user_email = "dev@example.com"
    exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=30)
    token = jwt.encode(
        {"email": user_email, "exp": int(exp.timestamp())},
        TEST_HMAC_SECRET,
        algorithm="HS256",
    )

    set_frappe_config(
        {
            "vouch_jwt_enabled": True,
            "vouch_header_name": "Authorization",
            "vouch_header_prefix": "Bearer",
            "vouch_jwt_secret": TEST_HMAC_SECRET,
            "vouch_jwt_algorithms": ["HS256"],
            "vouch_email_claim": "email",
            "vouch_cache_disabled": True,
            "vouch_enable_logging": True,
        }
    )
    frappe_mock.get_request_header.return_value = f"Bearer {token}"
    frappe_mock.db.exists.return_value = True

    validate_vouch_jwt()

    frappe_mock.set_user.assert_called_once_with(user_email)


def test_validate_vouch_jwt_auto_creates_user():
    user_email = "newbie@example.com"
    exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=30)
    token = jwt.encode(
        {
            "email": user_email,
            "given_name": "Alex",
            "family_name": "Doe",
            "exp": int(exp.timestamp()),
        },
        TEST_HMAC_SECRET,
        algorithm="HS256",
    )

    set_frappe_config(
        {
            "vouch_jwt_enabled": True,
            "vouch_header_name": "X-Vouch-Token",
            "vouch_header_prefix": "",
            "vouch_jwt_secret": TEST_HMAC_SECRET,
            "vouch_jwt_algorithms": ["HS256"],
            "vouch_email_claim": "email",
            "vouch_create_user": True,
            "vouch_cache_disabled": True,
            "vouch_enable_logging": True,
        }
    )
    frappe_mock.get_request_header.return_value = token

    # User does not exist, Role exists
    frappe_mock.db.exists.side_effect = lambda dt, val=None: (
        False if dt == "User" else True
    )

    fake_user_doc = MagicMock()
    frappe_mock.new_doc.return_value = fake_user_doc

    validate_vouch_jwt()

    fake_user_doc.insert.assert_called_once()
    frappe_mock.set_user.assert_called_once_with(user_email)


def test_validate_vouch_jwt_expired_token():
    expired = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
    token = jwt.encode(
        {"email": "expired@example.com", "exp": int(expired.timestamp())},
        TEST_HMAC_SECRET,
        algorithm="HS256",
    )

    set_frappe_config(
        {
            "vouch_jwt_enabled": True,
            "vouch_header_name": "Authorization",
            "vouch_header_prefix": "Bearer",
            "vouch_jwt_secret": TEST_HMAC_SECRET,
            "vouch_cache_disabled": True,
            "vouch_enable_logging": False,
        }
    )
    frappe_mock.get_request_header.return_value = f"Bearer {token}"

    validate_vouch_jwt()
    frappe_mock.set_user.assert_not_called()


def test_validate_vouch_jwt_invalid_signature():
    # Token signed with a different key
    bad_secret = "completely_wrong_secret_key_that_does_not_match!"
    user_email = "attacker@example.com"
    exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=30)
    token = jwt.encode(
        {"email": user_email, "exp": int(exp.timestamp())},
        bad_secret,
        algorithm="HS256",
    )

    set_frappe_config(
        {
            "vouch_jwt_enabled": True,
            "vouch_header_name": "Authorization",
            "vouch_header_prefix": "Bearer",
            "vouch_jwt_secret": TEST_HMAC_SECRET,
            "vouch_jwt_algorithms": ["HS256"],
            "vouch_email_claim": "email",
            "vouch_cache_disabled": True,
            "vouch_enable_logging": False,
        }
    )
    frappe_mock.get_request_header.return_value = f"Bearer {token}"

    validate_vouch_jwt()
    frappe_mock.set_user.assert_not_called()


def test_preserves_form_dict_after_set_user():
    token = jwt.encode(
        {
            "email": "test@example.com",
            "exp": int(
                (
                    datetime.datetime.now(datetime.timezone.utc)
                    + datetime.timedelta(hours=1)
                ).timestamp()
            ),
        },
        TEST_HMAC_SECRET,
        algorithm="HS256",
    )

    set_frappe_config(
        {
            "vouch_jwt_enabled": True,
            "vouch_header_name": "Authorization",
            "vouch_header_prefix": "Bearer",
            "vouch_jwt_secret": TEST_HMAC_SECRET,
            "vouch_email_claim": "email",
            "vouch_cache_disabled": True,
            "vouch_enable_logging": False,
        }
    )
    frappe_mock.get_request_header.return_value = f"Bearer {token}"
    frappe_mock.db.exists.return_value = True

    frappe_mock.local.form_dict = {"cmd": "ping", "data": "123"}

    def reset_form_dict(user):
        frappe_mock.local.form_dict = {}

    frappe_mock.set_user.side_effect = reset_form_dict

    validate_vouch_jwt()

    assert frappe_mock.local.form_dict == {"cmd": "ping", "data": "123"}
