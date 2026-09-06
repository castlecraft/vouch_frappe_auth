import datetime
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
        # Claim mapping: Vouch standard token payload uses "username", "email", or "customClaims"
        "email_claim": conf.get(
            "vouch_email_claim",
            os.getenv("VOUCH_EMAIL_CLAIM", "username"),
        ),
        "create_user": conf.get(
            "vouch_create_user",
            os.getenv("VOUCH_CREATE_USER", "0") in ("1", "true", "True"),
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
            os.getenv("VOUCH_ENABLE_LOGGING", "0") in ("1", "true", "True"),
        ),
    }


def extract_token(config: dict) -> str | None:
    header_name = config["header_name"]
    header_val = frappe.get_request_header(header_name, "").strip()

    if not header_val:
        return None

    prefix = (config["header_prefix"] or "").strip()
    if prefix:
        if header_val.lower().startswith(prefix.lower() + " "):
            start_index = len(prefix) + 1
            return header_val[start_index:].strip()
        return None

    return header_val


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

        # 2. Decode & verify HMAC signature
        if not payload:
            payload = jwt.decode(
                token,
                key=config["jwt_secret"],
                algorithms=["HS256"],
                options={"verify_aud": False},
            )

        # 3. Resolve user identity from claims
        email = payload.get(config["email_claim"])
        if not email:
            return

        user_exists = frappe.db.exists("User", email)

        if not user_exists and config["create_user"]:
            create_vouch_user(email, payload, config)
            user_exists = True

        if user_exists:
            frappe.set_user(email)

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
    user.first_name = (
        payload.get("given_name") or payload.get("name") or email.split("@")[0]
    )
    user.last_name = payload.get("family_name") or ""
    user.enabled = 1
    user.flags.ignore_permissions = 1
    user.flags.no_welcome_mail = True

    for role in config.get("default_roles", []):
        if frappe.db.exists("Role", role):
            user.append("roles", {"role": role})

    user.insert()
    frappe.db.commit()
