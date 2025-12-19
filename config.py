import os
from datetime import timedelta


class Config:
    """Base configuration for the Loan Approval Backend.

    Notes:
    - Use environment variables in production for secrets and DB path.
    - SESSION_COOKIE_SECURE should be True in production with HTTPS.
    """

    # App
    SECRET_KEY = os.environ.get("SECRET_KEY") or "change-me-in-production"
    JSON_SORT_KEYS = False

    # Database
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///" + os.path.join(BASE_DIR, "app.db")
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session / Cookies
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"
    # Set to True when running under HTTPS
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "True") == "True"

    # CSRF
    WTF_CSRF_CHECK_DEFAULT = True

    # Talisman / CSP defaults - allow minimal API usage; tighten for UI
    TALISMAN_FORCE_HTTPS = True
    # Example CSP, adjust for assets/domains in production
    CONTENT_SECURITY_POLICY = {
        "default-src": "'self'",
        "script-src": ["'self'"],
        "style-src": ["'self'"]
    }

    # Password hashing config for Argon2 (argon2-cffi) - tune for your environment
    ARGON2_TIME_COST = int(os.environ.get("ARGON2_TIME_COST", 2))
    ARGON2_MEMORY_COST = int(os.environ.get("ARGON2_MEMORY_COST", 102400))
    ARGON2_PARALLELISM = int(os.environ.get("ARGON2_PARALLELISM", 8))

    # Logging
    LOG_FILE = os.environ.get("LOG_FILE", os.path.join(BASE_DIR, "loan_backend.log"))


class DevelopmentConfig(Config):
    DEBUG = True
    SESSION_COOKIE_SECURE = False
    TALISMAN_FORCE_HTTPS = False


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    TALISMAN_FORCE_HTTPS = True


config = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
