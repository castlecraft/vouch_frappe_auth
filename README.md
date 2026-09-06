### Vouch Frappe Auth

Frappe middleware for Vouch auth

### Installation

You can install this app using the [bench](https://github.com/frappe/bench) CLI:

```bash
cd $PATH_TO_YOUR_BENCH
bench get-app $URL_OF_THIS_REPO --branch develop
bench install-app vouch_frappe_auth
```

### Configuration

Option A: Dedicated Header (e.g., `X-Vouch-Jwt: <jwt>`)

```json
{
  "vouch_jwt_enabled": true,
  "vouch_header_name": "X-Vouch-Jwt",
  "vouch_header_prefix": "",
  "vouch_jwt_secret": "your-vouch-secret-key",
  "vouch_jwt_algorithms": ["HS256"],
  "vouch_email_claim": "email",
  "vouch_create_user": true,
  "vouch_enable_logging": true
}
```

Option B: Standard Authorization Header (`Authorization: Bearer <jwt>`) with JWKS/RS256

```json
{
  "vouch_jwt_enabled": true,
  "vouch_header_name": "Authorization",
  "vouch_header_prefix": "Bearer",
  "vouch_jwt_secret": "your-vouch-jwt-secret",
  "vouch_email_claim": "email",
  "vouch_create_user": false,
  "vouch_enable_logging": true
}
```

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
