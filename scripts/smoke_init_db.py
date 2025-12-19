"""Smoke test: initialize the Flask app and create database tables.

Run this from the project root using the workspace Python. It will import
the app factory and run `db.create_all()` inside an app context.
"""
import sys
import traceback

try:
    # Import app.py by path to avoid module resolution issues
    import importlib.util
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[1]
    app_path = repo_root / 'app.py'
    # Ensure repo root is on sys.path so app-level imports work
    import sys
    sys.path.insert(0, str(repo_root))

    spec = importlib.util.spec_from_file_location('app_module', str(app_path))
    app_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app_module)

    create_app = getattr(app_module, 'create_app')
    app = create_app('default')
    with app.app_context():
        from models import db
        db.create_all()
        print('OK: Database initialized')
        print('DB URI:', app.config.get('SQLALCHEMY_DATABASE_URI'))
    sys.exit(0)
except Exception:
    print('ERROR: Smoke test failed')
    traceback.print_exc()
    sys.exit(2)
