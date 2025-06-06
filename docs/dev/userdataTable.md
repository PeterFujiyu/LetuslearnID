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
| `credential_id`     | TEXT          | *(deprecated)* |
| `passkey_public`    | TEXT          | *(deprecated)* |
| `counter`           | INTEGER       | *(deprecated)* |
| `created_at`        | DATETIME      | Record creation time                             |
| `updated_at`        | DATETIME      | Last update time                                 |

This design allows storage of password changes, email updates, two‑factor settings, passkeys and single‑use backup codes for account recovery.

## Passkeys Table

| Column name   | Type       | Description |
|---------------|-----------|-------------|
| `id`          | INTEGER PK| Unique key identifier |
| `user_id`     | INTEGER   | Owner user id |
| `credential_id` | TEXT    | Credential ID for WebAuthn |
| `public_key`  | TEXT      | Stored public key |
| `counter`     | INTEGER   | Signature counter |
