import os

class Config:
    SECRET_KEY = 'dev-secret-key-change-later'

    # File paths
    DATA_DIR = 'data'
    LOGS_DIR = 'logs'
    UPLOADS_DIR = 'data/uploads'
    USERS_FILE = 'data/users.json'
    SESSIONS_FILE = 'data/sessions.json'
    DOCUMENTS_FILE = 'data/documents.json'

    ENV = os.environ.get('FLASK_ENV', 'development')