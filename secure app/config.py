import os
import secrets

class Config:
    # Secret key for Flask (use env var in production)
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))

    # File paths
    DATA_DIR = 'data'
    LOGS_DIR = 'logs'
    UPLOADS_DIR = 'data/uploads'
    USERS_FILE = 'data/users.json'
    SESSIONS_FILE = 'data/sessions.json'
    DOCUMENTS_FILE = 'data/documents.json'
    ENCRYPTION_KEY_FILE = 'data/secret.key'
    SECURITY_LOG = 'logs/security.log'
    ACCESS_LOG = 'logs/access.log'

    # Session settings
    SESSION_TIMEOUT = 1800  # 30 minutes

    # Account lockout (added week 3)
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_DURATION = 900  # 15 minutes

    # Rate limiting per IP (added week 3)
    RATE_LIMIT_ATTEMPTS = 10
    RATE_LIMIT_WINDOW = 60  # seconds

    # Password requirements (added week 3)
    PASSWORD_MIN_LENGTH = 12

    # Username requirements (added week 3)
    USERNAME_MIN = 3
    USERNAME_MAX = 20

    # File upload settings (hardened week 3)
    ALLOWED_EXTENSIONS = {'pdf', 'txt', 'docx', 'png', 'jpg', 'jpeg'}
    MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB

    # TLS
    SSL_CERT = os.environ.get('SSL_CERT', 'cert.pem')
    SSL_KEY = os.environ.get('SSL_KEY', 'key.pem')

    ENV = os.environ.get('FLASK_ENV', 'development')