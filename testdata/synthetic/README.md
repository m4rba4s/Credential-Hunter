# Synthetic Sensitive Fixtures

These fixtures contain intentionally generated credentials that mimic real
secrets (AWS keys, GitHub tokens, etc.) while remaining completely fake.
They are used by integration tests to ensure the detection engine reliably
identifies high-value secrets in realistic mixed-content blobs.

Files:
- `aws_and_github.env` – `.env` style file with AWS and GitHub tokens.
- `pipeline_dump.txt` – Mixed log output containing Azure client secrets,
  database URLs, and JWT samples sprinkled through normal text.
- `creds/mimikatz_dump.log` – Synthetic mimikatz-style output with fake logon
  sessions, NTLM hashes, and cleartext passwords for detection tuning.
- `creds/offline_backup.pfx` – Placeholder PKCS#12 archive to exercise bundle
  path detection (.pfx/.p12).

Feel free to add additional synthetic samples here, but avoid embedding any
actual production secrets.
