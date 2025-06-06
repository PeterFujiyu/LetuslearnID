# User Data Table

The following table describes a simple relational schema for storing user accounts and security settings. Field types may be adjusted to match the chosen database.

| Column name         | Type          | Description                                      |
|---------------------|---------------|--------------------------------------------------|
| `id`                | INTEGER PK    | Unique user identifier                           |
| `username`          | VARCHAR       | Login name, unique                               |
| `password_hash`     | VARCHAR       | Hash of user password                            |
| `email`             | VARCHAR       | User email address                               |
| `totp_secret`       | VARCHAR       | Secret used for TOTP authenticator apps |
| `backup_codes`      | TEXT          | JSON array of one‑time backup codes |
| `credential_id`     | TEXT          | Credential ID of registered passkey |
| `passkey_public`    | TEXT          | Public key data for passkeys (WebAuthn) |
| `counter`           | INTEGER       | WebAuthn signature counter |
| `created_at`        | DATETIME      | Record creation time                             |
| `updated_at`        | DATETIME      | Last update time                                 |

This design allows storage of password changes, email updates, two‑factor settings, passkeys and single‑use backup codes for account recovery.
