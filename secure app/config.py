import os
import secrets

class Config:
    #secret key stuff, but always actually uses the secrets.token_hex(32) because we never set a secret key 
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))

    #file paths
    DATA_DIR = 'data'
    LOGS_DIR = 'logs'
    UPLOADS_DIR = 'data/uploads'
    USERS_FILE = 'data/users.json'
    SESSIONS_FILE = 'data/sessions.json'
    DOCUMENTS_FILE = 'data/documents.json'
    ENCRYPTION_KEY_FILE = 'data/secret.key'
    SECURITY_LOG = 'logs/security.log'
    ACCESS_LOG = 'logs/access.log'

    #session timer
    SESSION_TIMEOUT = 1800  # 30 minutes

    #account lockout stuff
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_DURATION = 900  # 15 minutes

    #rate limiting
    RATE_LIMIT_ATTEMPTS = 10
    #60 seconds
    RATE_LIMIT_WINDOW = 60  

    #minimum password length
    PASSWORD_MIN_LENGTH = 12

    #username requirements
    USERNAME_MIN = 3
    USERNAME_MAX = 20

    #file upload restrictions
    ALLOWED_EXTENSIONS = {'pdf', 'txt', 'docx', 'png', 'jpg', 'jpeg'}
    #10 MB limit
    MAX_UPLOAD_BYTES = 10 * 1024 * 1024  

    #certificate and key stuff
    SSL_CERT = os.environ.get('SSL_CERT', 'cert.pem')
    SSL_KEY = os.environ.get('SSL_KEY', 'key.pem')

    #we never set flask env, so we just always use development again
    ENV = os.environ.get('FLASK_ENV', 'development')