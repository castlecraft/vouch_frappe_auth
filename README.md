### Vouch Frappe Auth

Frappe middleware for Vouch auth

### Installation

You can install this app using the [bench](https://github.com/frappe/bench) CLI:

```bash
cd $PATH_TO_YOUR_BENCH
bench get-app $URL_OF_THIS_REPO --branch develop
bench install-app vouch_frappe_auth
```

### How Authentication Works

`vouch_frappe_auth` is a Frappe authentication hook designed specifically for **Vouch Proxy** using Vouch's internal HS256 JWT signature (`vouch.jwt.secret`).

#### Cookie & Token Extraction

On incoming HTTP requests, the middleware extracts the JWT in the following order:

1. **Request Header**: Value from configured header (e.g., `X-Vouch-Token` or `Authorization: Bearer <token>`).
2. **`VouchCookie`**: If no header is present, extracts the `VouchCookie` sent by the browser. Vouch compresses its JWT using `gzip` and encodes it in URL-safe base64. The middleware automatically decodes and decompresses the `VouchCookie` to retrieve the original Vouch JWT.

#### Session Lifetime & Upstream IdP

- **Internal Vouch Token Only**: Authentication validates the symmetric HMAC (`HS256`) signature signed by Vouch Proxy using `vouch_jwt_secret` (`vouch.jwt.secret` in Vouch config).
- **Session Duration in Vouch**: The middleware does not poll or sync short-lived (e.g. 1-hour) upstream IdP token expirations directly once the Vouch session is established. The active session length in Frappe is bounded by the Vouch cookie/JWT expiration (`vouch.cookie.maxAge` in Vouch config).
- **Longer Browser Sessions**: To keep users logged in for longer periods in Frappe, configure the browser session duration in Vouch Proxy (`vouch.cookie.maxAge` / session timeout).

### Configuration

Set these keys in your `site_config.json` or `common_site_config.json`:

#### Option A: `VouchCookie` / Dedicated Header (Default)

```json
{
  "vouch_jwt_enabled": 1,
  "vouch_header_name": "X-Vouch-Token",
  "vouch_header_prefix": "",
  "vouch_jwt_secret": "your_vouch_jwt_secret_32_bytes_min!!",
  "vouch_jwt_algorithms": ["HS256"],
  "vouch_email_claim": "username",
  "vouch_create_user": 1,
  "vouch_default_roles": ["System User"],
  "vouch_cache_disabled": 0,
  "vouch_enable_logging": 1
}
```

#### Option B: Authorization Header (`Authorization: Bearer <jwt>`)

```json
{
  "vouch_jwt_enabled": 1,
  "vouch_header_name": "Authorization",
  "vouch_header_prefix": "Bearer",
  "vouch_jwt_secret": "your_vouch_jwt_secret_32_bytes_min!!",
  "vouch_jwt_algorithms": ["HS256"],
  "vouch_email_claim": "email",
  "vouch_create_user": 1,
  "vouch_default_roles": ["System User"],
  "vouch_cache_disabled": 0,
  "vouch_enable_logging": 1
}
```

#### Configuration Options

| Option                 | Default           | Description                                                                 |
| ---------------------- | ----------------- | --------------------------------------------------------------------------- |
| `vouch_jwt_enabled`    | `0`               | Enable Vouch JWT authentication hook (`1` / `true`)                         |
| `vouch_jwt_secret`     | `null`            | Symmetric secret configured in Vouch Proxy (`vouch.jwt.secret`)             |
| `vouch_jwt_algorithms` | `["HS256"]`       | Allowed JWT signing algorithms                                              |
| `vouch_header_name`    | `"X-Vouch-Token"` | HTTP header to inspect for JWT                                              |
| `vouch_header_prefix`  | `""`              | Optional prefix in header (e.g. `"Bearer"`)                                 |
| `vouch_email_claim`    | `"username"`      | Claim name mapped to Frappe User (`"username"`, `"email"`, or custom claim) |
| `vouch_create_user`    | `1`               | Automatically create User document if not existing                          |
| `vouch_default_roles`  | `["System User"]` | Roles assigned to newly created users                                       |
| `vouch_cache_disabled` | `0`               | Set to `1` to disable Redis token verification caching                      |
| `vouch_enable_logging` | `1`               | Log authentication failures to Frappe Error Log                             |

### Contributing

This app uses `pre-commit` for code formatting and linting. Please [install pre-commit](https://pre-commit.com/#installation) and enable it for this repository:

```bash
cd apps/vouch_frappe_auth
pre-commit install
```

Pre-commit is configured to use the following tools for checking and formatting your code:

- ruff
- eslint
- prettier
- pyupgrade

### License

apache-2.0
