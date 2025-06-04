# User Data Table

The following table describes a simple relational schema for storing user accounts and security settings. Field types may be adjusted to match the chosen database.

| Column name         | Type          | Description                                      |
|---------------------|---------------|--------------------------------------------------|
| `id`                | INTEGER PK    | Unique user identifier                           |
| `username`          | VARCHAR       | Login name, unique                               |
| `password_hash`     | VARCHAR       | Hash of user password                            |
| `email`             | VARCHAR       | User email address                               |
| `two_factor_enabled`| BOOLEAN       | Whether two‑factor authentication is enabled     |
| `two_factor_secret` | VARCHAR       | Secret or seed used for TOTP / authenticator app |
| `passkey_public`    | TEXT          | Public credential data for passkeys (WebAuthn)   |
| `backup_codes`      | TEXT          | Comma separated one‑time backup codes            |
| `created_at`        | DATETIME      | Record creation time                             |
| `updated_at`        | DATETIME      | Last update time                                 |

This design allows storage of password changes, email updates, two‑factor settings, passkeys and single‑use backup codes for account recovery.
