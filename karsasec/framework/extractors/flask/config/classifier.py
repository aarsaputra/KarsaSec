"""Sensitive Configuration Key Classifier for Flask Applications."""

from __future__ import annotations


class SensitiveConfigClassifier:
    """Classifies Flask configuration keys by category and security sensitivity."""

    SENSITIVE_PATTERNS = (
        "SECRET", "PASSWORD", "PASS", "TOKEN", "JWT", "PRIVATE_KEY", "CERT", "KEY",
        "COOKIE", "SESSION", "DATABASE", "DB", "REDIS", "CACHE", "SMTP", "MAIL",
        "CSRF", "CORS", "SSL", "TLS", "AUTH", "API_KEY", "CREDENTIAL"
    )

    CATEGORY_MAP = {
        "DEBUG": "app",
        "TESTING": "app",
        "ENV": "app",
        "SECRET_KEY": "security",
        "SECURITY_PASSWORD_SALT": "security",
        "SESSION_COOKIE_SECURE": "session",
        "SESSION_COOKIE_HTTPONLY": "session",
        "SESSION_COOKIE_SAMESITE": "session",
        "SESSION_COOKIE_NAME": "session",
        "PERMANENT_SESSION_LIFETIME": "session",
        "REMEMBER_COOKIE_SECURE": "cookie",
        "REMEMBER_COOKIE_HTTPONLY": "cookie",
        "WTF_CSRF_ENABLED": "csrf",
        "WTF_CSRF_SECRET_KEY": "csrf",
        "MAX_CONTENT_LENGTH": "upload",
        "TEMPLATES_AUTO_RELOAD": "template",
        "LOGGER_HANDLER_POLICY": "logging",
        "SQLALCHEMY_DATABASE_URI": "database",
        "SQLALCHEMY_TRACK_MODIFICATIONS": "database",
        "CACHE_TYPE": "cache",
        "CACHE_REDIS_URL": "cache",
    }

    @classmethod
    def classify(cls, key: str) -> tuple[str, bool]:
        """Returns tuple of (category, is_sensitive) for a given configuration key."""
        upper_key = key.upper()

        # Check explicit category map
        category = cls.CATEGORY_MAP.get(upper_key)

        if not category:
            if "SESSION" in upper_key:
                category = "session"
            elif "CSRF" in upper_key:
                category = "csrf"
            elif "COOKIE" in upper_key:
                category = "cookie"
            elif "UPLOAD" in upper_key or "LENGTH" in upper_key:
                category = "upload"
            elif "TEMPLATE" in upper_key:
                category = "template"
            elif "LOG" in upper_key:
                category = "logging"
            elif any(db_word in upper_key for db_word in ("DATABASE", "DB", "SQL", "MONGO", "POSTGRES")):
                category = "database"
            elif "CACHE" in upper_key or "REDIS" in upper_key:
                category = "cache"
            elif any(sec_word in upper_key for sec_word in ("SECRET", "PASS", "TOKEN", "JWT", "KEY", "AUTH", "CREDENTIAL")):
                category = "security"
            else:
                category = "app"

        is_sensitive = any(pat in upper_key for pat in cls.SENSITIVE_PATTERNS)
        return category, is_sensitive
