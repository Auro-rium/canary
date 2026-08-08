# Database migrations

`models.py` keeps local SQLite upgrades backward-compatible with the original
Canary database by adding nullable columns and creating new tables at startup.
`001_cutc_release_domain.sql` is the equivalent PostgreSQL baseline for a
queue/worker deployment. Run it with the deployment's migration runner before
starting API and worker processes; do not apply it to SQLite.
