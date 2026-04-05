"""
session_manager.py — Added in week 3.
Replaces uuid4 session tokens from week 2 with:
  - secrets.token_urlsafe(32) for cryptographically secure tokens
  - 30-minute inactivity timeout
  - IP address and user-agent binding stored per session
"""
import secrets
import time
from config import Config
from models import load_sessions, save_sessions
from logger import log_security


class SessionManager:
    def __init__(self, timeout: int = Config.SESSION_TIMEOUT):
        self.timeout = timeout

    def create(self, username: str, ip: str, ua: str) -> str:
        # secrets.token_urlsafe(32) replaced uuid4 from week 2
        token = secrets.token_urlsafe(32)
        sessions = load_sessions()
        sessions[token] = {
            'username': username,
            'created_at': time.time(),
            'last_activity': time.time(),
            'ip_address': ip,
            'user_agent': ua,
        }
        save_sessions(sessions)
        log_security('SESSION_CREATED', user_id=username,
                     details={'ip': ip}, ip=ip, ua=ua)
        return token

    def validate(self, token: str):
        if not token:
            return None
        sessions = load_sessions()
        session = sessions.get(token)
        if not session:
            return None
        # Inactivity timeout check
        if time.time() - session['last_activity'] > self.timeout:
            self.destroy(token)
            return None
        # Refresh last activity
        session['last_activity'] = time.time()
        sessions[token] = session
        save_sessions(sessions)
        return session

    def destroy(self, token: str) -> None:
        sessions = load_sessions()
        session = sessions.pop(token, None)
        if session:
            save_sessions(sessions)
            log_security('SESSION_DESTROYED',
                         user_id=session.get('username'),
                         ip=session.get('ip_address'))

    def destroy_all_for_user(self, username: str) -> None:
        """Invalidate all sessions for a user (e.g. on password change)."""
        sessions = load_sessions()
        to_remove = [t for t, s in sessions.items()
                     if s.get('username') == username]
        for t in to_remove:
            del sessions[t]
        save_sessions(sessions)
        log_security('ALL_SESSIONS_DESTROYED', user_id=username)


session_manager = SessionManager()