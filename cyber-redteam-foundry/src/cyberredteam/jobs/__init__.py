"""WP7: jobs, workers and the control plane (kill switch, cancel, SSE resume).

Import submodules directly; this package ``__init__`` stays import-light so
Alembic's ``env.py`` can import ``jobs.tables`` without pulling in procrastinate.
"""
