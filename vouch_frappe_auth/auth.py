import base64
import datetime
import gzip
import json
import os
import traceback

import frappe
import jwt


def get_vouch_config():
    conf = frappe.conf or {}

    return {
        "enabled": conf.get(
            "vouch_jwt_enabled",
            os.getenv("VOUCH_JWT_ENABLED", "0") in ("1", "true", "True"),
        ),
        # Header settings: e.g., "X-Vouch-Token" (no prefix) or "Authorization" ("Bearer")
        "header_name": conf.get(
            "vouch_header_name",
            os.getenv("VOUCH_HEADER_NAME", "X-Vouch-Token"),
        ),
        "header_prefix": conf.get(
            "vouch_header_prefix",
            os.getenv("VOUCH_HEADER_PREFIX", ""),
        ),
        # Vouch Proxy symmetric secret (vouch.jwt.secret)
        "jwt_secret": conf.get(
            "vouch_jwt_secret",
            os.getenv("VOUCH_JWT_SECRET"),
        ),
        "algorithms": conf.get(
            "vouch_jwt_algorithms",
            json.loads(os.getenv("VOUCH_JWT_ALGORITHMS", '["HS256"]')),
        ),
        # Claim mapping: Vouch standard token payload uses "username", "email", or "CustomClaims"
        "email_claim": conf.get(
            "vouch_email_claim",
            os.getenv("VOUCH_EMAIL_CLAIM", "username"),
        ),
        "create_user": conf.get(
            "vouch_create_user",
            os.getenv("VOUCH_CREATE_USER", "1") in ("1", "true", "True"),
        ),
        "default_roles": conf.get(
            "vouch_default_roles",
            json.loads(os.getenv("VOUCH_DEFAULT_ROLES", '["System User"]')),
        ),
        "cache_disabled": conf.get(
            "vouch_cache_disabled",
            os.getenv("VOUCH_CACHE_DISABLED", "0") in ("1", "true", "True"),
        ),
        "enable_logging": conf.get(
            "vouch_enable_logging",
            os.getenv("VOUCH_ENABLE_LOGGING", "1") in ("1", "true", "True"),
        ),
    }


def extract_token(config: dict) -> str | None:
    # 1. Try configured header (e.g. X-Vouch-Token or Authorization: Bearer ...)
    header_name = config["header_name"]
    header_val = frappe.get_request_header(header_name)
    if header_val and isinstance(header_val, str) and header_val.strip():
        header_val = header_val.strip()
        prefix = (config["header_prefix"] or "").strip()
        if prefix:
            if header_val.lower().startswith(prefix.lower() + " "):
                start_index = len(prefix) + 1
                return header_val[start_index:].strip()
            return None
        return header_val

    # 2. Fallback: Extract from Cookie header or request.cookies
    vouch_cookie = None
    cookie_str = (
        frappe.get_request_header("Cookie") or frappe.get_request_header("cookie") or ""
    )
    if isinstance(cookie_str, str) and "VouchCookie=" in cookie_str:
        for item in cookie_str.split(";"):
            item = item.strip()
            if item.startswith("VouchCookie="):
                vouch_cookie = item.split("=", 1)[1]
                break

    if not vouch_cookie:
        req = getattr(frappe, "request", None)
        cookies = getattr(req, "cookies", None)
        if cookies and (isinstance(cookies, dict) or hasattr(cookies, "get")):
            val = cookies.get("VouchCookie")
            if val and isinstance(val, str):
                vouch_cookie = val

    if vouch_cookie and isinstance(vouch_cookie, str):
        try:
            clean_cookie = vouch_cookie.strip()
            clean_cookie += "=" * (-len(clean_cookie) % 4)
            compressed = base64.urlsafe_b64decode(clean_cookie)
            return gzip.decompress(compressed).decode("utf-8")
        except Exception:
            if "." in clean_cookie and len(clean_cookie.split(".")) == 3:
                return clean_cookie

    return None


def resolve_email_from_payload(payload: dict, claim_key: str) -> str | None:
    """Resolves email from direct claims, CustomClaims, or fallback fields."""
    if not payload:
        return None

    # Check direct claim
    if payload.get(claim_key):
        return str(payload[claim_key])

    # Check nested Vouch CustomClaims dict
    for custom_key in ("CustomClaims", "customClaims", "custom_claims"):
        custom = payload.get(custom_key)
        if isinstance(custom, dict):
            if custom.get(claim_key):
                return str(custom[claim_key])
            if custom.get("email"):
                return str(custom["email"])
            if custom.get("username"):
                return str(custom["username"])

    # Standard fallback fields
    return payload.get("email") or payload.get("username") or payload.get("sub")


def validate_vouch_jwt():
    """
    Frappe auth_hook to authenticate users via Vouch Proxy JWT.
    """
    config = get_vouch_config()
    if not config["enabled"] or not config["jwt_secret"]:
        return

    token = extract_token(config)
    if not token:
        return

    try:
        now = datetime.datetime.now(datetime.timezone.utc)
        payload = None

        # 1. Check Redis cache
        if not config["cache_disabled"]:
            cached_data = frappe.cache().get_value(f"vouch_jwt|{token}")
            if cached_data:
                cached_payload = json.loads(cached_data)
                exp = cached_payload.get("exp")
                if exp and now < datetime.datetime.fromtimestamp(
                    int(exp), tz=datetime.timezone.utc
                ):
                    payload = cached_payload
                else:
                    frappe.cache().delete_key(f"vouch_jwt|{token}")

        # 2. Decode & verify HMAC signature using shared Vouch secret
        if not payload:
            payload = jwt.decode(
                token,
                key=config["jwt_secret"],
                algorithms=config["algorithms"],
                options={"verify_aud": False},
            )

        # 3. Resolve user identity from claims (direct, CustomClaims, or fallback)
        email = resolve_email_from_payload(payload, config["email_claim"])
        if not email:
            return

        user_exists = frappe.db.exists("User", email)

        if not user_exists and config["create_user"]:
            create_vouch_user(email, payload, config)
            user_exists = True

        if user_exists:
            saved_form_dict = getattr(getattr(frappe, "local", None), "form_dict", None)
            frappe.set_user(email)
            if hasattr(frappe, "session"):
                frappe.session.user = email
            if (
                hasattr(getattr(frappe, "local", None), "session")
                and frappe.local.session
            ):
                frappe.local.session.user = email
            if (
                hasattr(getattr(frappe, "local", None), "login_manager")
                and frappe.local.login_manager
            ):
                frappe.local.login_manager.user = email
            if saved_form_dict is not None and getattr(frappe, "local", None):
                frappe.local.form_dict = saved_form_dict

            # 4. Cache verified payload up to token exp
            if not config["cache_disabled"] and payload.get("exp"):
                exp_dt = datetime.datetime.fromtimestamp(
                    int(payload["exp"]), tz=datetime.timezone.utc
                )
                ttl = int((exp_dt - now).total_seconds())
                if ttl > 0:
                    frappe.cache().set_value(
                        f"vouch_jwt|{token}",
                        json.dumps(payload),
                        expires_in_sec=ttl,
                    )

    except Exception:
        if config["enable_logging"]:
            frappe.log_error(
                title="Vouch JWT Auth Failed",
                message=traceback.format_exc(),
            )


def create_vouch_user(email: str, payload: dict, config: dict):
    user = frappe.new_doc("User")
    user.name = email
    user.email = email

    # Resolve first and last name from payload or CustomClaims
    custom_claims = payload.get("CustomClaims") or payload.get("customClaims") or {}
    first_name = (
        payload.get("given_name")
        or payload.get("name")
        or custom_claims.get("given_name")
        or custom_claims.get("name")
        or email.split("@")[0]
    )
    last_name = payload.get("family_name") or custom_claims.get("family_name") or ""

    user.first_name = first_name
    user.last_name = last_name
    user.enabled = 1
    user.flags.ignore_permissions = 1
    user.flags.no_welcome_mail = True

    for role in config.get("default_roles", []):
        if frappe.db.exists("Role", role):
            user.append("roles", {"role": role})

    user.insert()
    frappe.db.commit()
