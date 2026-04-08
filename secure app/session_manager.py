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
    #run this automatically, default timeout is 30 min unless a value is entered
    def __init__(self, timeout: int = Config.SESSION_TIMEOUT):
        self.timeout = timeout

    def create(self, username: str, ip: str, ua: str) -> str:
        #using the secrets import to generate a random string
        token = secrets.token_urlsafe(32)
        #load the sessions dictionary 
        sessions = load_sessions()
        #using the token as a key in this dictionary, create another dictionary inside
        #with the sessions information like who it is, when the session started, when was the last
        #time they did something, their ip address, and the user agent (operating system/browser) 
        #getting the user agent and IP for auditing purposes!!
        sessions[token] = {
            'username': username,
            'created_at': time.time(),
            'last_activity': time.time(),
            'ip_address': ip,
            'user_agent': ua,
        }
        #save the new updated dictionary
        save_sessions(sessions)
        #log the session being created
        log_security('SESSION_CREATED', user_id=username,
                     details={'ip': ip}, ip=ip, ua=ua)
        #return the token to set the cookie in app.py login
        return token

    def validate(self, token: str):
        #if there is no token just return
        #this would be the case if:
        #1. new user logs on (never used the website before)
        #2. existing user logged out and their cookie was deleted
        #3. someone manually cleared their cookies
        if not token:
            return None
        #load sessions dictionary
        sessions = load_sessions()
        #use the token to find the entry in the dictionary
        session = sessions.get(token)
        #if nothing was returned that means their session doesnt exist
        #this could be the case if:
        #1. token expired and was deleted
        #2. user logged out on another device (or changed password so everything for this user is wiped)
        #3. someone is trying random tokens
        #4. app restarted and deleted the sessions
        if not session:
            return None
        #check if the curent time - last recorded activity time, and if it is bigger than the
        #timeout timer, then destroy the token
        if time.time() - session['last_activity'] > self.timeout:
            #the session expired, so destroy the token 
            self.destroy(token)
            #person is not logged in anymore
            return None
        #if it makes it here, then the session is still valid so reset the last activity time to
        #the current time
        session['last_activity'] = time.time()
        #write the updated session back to the dictionary
        sessions[token] = session
        #save the dictionary of sessions json after updating it
        save_sessions(sessions)
        #gives session back in auth.py to find out whos logged in
        return session

    def destroy(self, token: str) -> None:
        #loads the sessions json
        sessions = load_sessions()
        #pops the session from the dictionary
        session = sessions.pop(token, None)
        #only if the session existed (if session is not None), save the updated sessions and 
        #log the destruction of the session
        if session:
            save_sessions(sessions)
            log_security('SESSION_DESTROYED',
                         user_id=session.get('username'),
                         ip=session.get('ip_address'))

    def destroy_all_for_user(self, username: str) -> None:
        """Invalidate all sessions for a user (e.g. on password change)."""
        #load the sessions json
        sessions = load_sessions()
        #find the sessions who has the same username, adds it to a list
        to_remove = [t for t, s in sessions.items()
                     if s.get('username') == username]
        #remove them from the sessions
        for t in to_remove:
            del sessions[t]
        #save updated sessions
        save_sessions(sessions)
        #log the destruction of all sessions
        log_security('ALL_SESSIONS_DESTROYED', user_id=username)

#creates an instance of it
session_manager = SessionManager()