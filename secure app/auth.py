"""
auth.py — Added in week 3.
Replaces the insecure plaintext login from week 2 with:
  - bcrypt password hashing (cost factor 12)
  - Input validation with regex whitelists
  - Account lockout after 5 failed attempts
  - Per-IP rate limiting
  - Role-based access control decorators
"""
import re
import time
import html
from functools import wraps

import bcrypt
from flask import g, request, redirect, abort

from config import Config
from models import (get_user_by_username, get_user_by_email,
                    save_user, check_rate_limit)
from session_manager import session_manager
from logger import log_security


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

#regular expressions to verify that these are in the correct format 

#only allow usernames that are 3-20 characters long with letters, numbers, and underscores ONLY
USERNAME_RE = re.compile(r'^[a-zA-Z0-9_]{3,20}$')

#one or more characters that are NOT @ \s (whitespace), then @, then more characters, then ., then more characters
#so an example is like helloworld@foobar.com
#helloworld (non @ and \s character)
#@
#foobar (more characters)
#.
#com (more characters)
EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')

#set of special characters that the email can have. AT LEAST ONE IS NEEDED
SPECIAL_CHARS = set('!@#$%^&*')


def validate_username(username: str):
    #does the entered USERNAME follow the correct username format?
    if not USERNAME_RE.match(username):
        return 'Username must be 3–20 characters: letters, numbers, underscore only.'
    return None


def validate_email(email: str):
    #does the entered EMAIL follow the correct email format?
    if not EMAIL_RE.match(email):
        return 'Invalid email address.'
    return None

#bunch of checks to see if it follows the correct PASSWORD format
def validate_password(password: str):

    #is the password at least 12 characters long??
    if len(password) < Config.PASSWORD_MIN_LENGTH:
        return f'Password must be at least {Config.PASSWORD_MIN_LENGTH} characters.'
    #are there any capital letters?
    if not any(c.isupper() for c in password):
        return 'Password must contain at least one uppercase letter.'
    #are there any lowercase letters?
    if not any(c.islower() for c in password):
        return 'Password must contain at least one lowercase letter.'
    #are there any numbers?
    if not any(c.isdigit() for c in password):
        return 'Password must contain at least one number.'
    #does the password have any of the characters in the SPECIAL_CHAR set?
    if not any(c in SPECIAL_CHARS for c in password):
        return f'Password must contain at least one special character ({", ".join(sorted(SPECIAL_CHARS))}).'
    
    #if it makes it here then its OK!
    return None


def sanitize(value: str) -> str:
    """Escape HTML special characters and strip whitespace."""
    return html.escape(value.strip())


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register_user(username: str, email: str,
                  password: str, confirm: str):
    
    #sanitize the username and email incase of any dangerous experssions/characters
    username = sanitize(username)
    email = sanitize(email)

    #go through each of the validation checks, and if any of them are false, then
    for check in (validate_username(username), validate_email(email), validate_password(password)):
        #if theres a value here, then its an error message
        if check:
            #retirm falase and the error message
            return False, check

    #if the entered password and the second time they type the password dont match, then return an error message
    #for example, entered password abc123, but their confirm was 321cba, it would be wrong
    if password != confirm:
        return False, 'Passwords do not match.'

    #check the dictionary of users, if it exists in there already, that means the name is taken
    if get_user_by_username(username):
        return False, 'Username already taken.'
    
    #same thing with users but with emails.  If its in the dictionary then the email is registered already
    if get_user_by_email(email):
        return False, 'Email already registered.'

    #generate the salt for the hash
    salt = bcrypt.gensalt(rounds=12)
    
    #hash the password WITH the salt
    #encode takes it as bytes, but we want to store the hash in a json so we need to decode it
    pw_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    #saving the user info
    save_user({
        'username': username,
        'email': email,
        #NOT PLAINTEXT
        'password_hash': pw_hash,   
        'role': 'guest',
        'created_at': time.time(),
        'failed_attempts': 0,
        'locked_until': None,
    })

    #log the success
    log_security('REGISTER_SUCCESS', user_id=username,
                 ip=request.remote_addr,
                 ua=request.headers.get('User-Agent'))
    return True, 'Account created successfully.'



#login stuff
#----------------------


def login_user(username: str, password: str):
    #getting the user ip 
    ip = request.remote_addr
    #what browser and operating system was used to send this request?
    ua = request.headers.get('User-Agent', '')

    #takes the ip and goes to models.py and checks how many times this ip has attempted to log in
    #if the attempts are over 10, then block the ip for a minute, dont even need to check who it is
    if not check_rate_limit(ip):
        log_security('RATE_LIMIT_HIT', user_id=username,
                     details={'ip': ip}, severity='WARNING', ip=ip, ua=ua)
        return False, 'Too many attempts. Please wait a minute.'

    #sanitize the username from 
    username = sanitize(username)
    #find the user in the users dictionary
    user = get_user_by_username(username)

    #if the username is incorrect or doesnt exist, make an error log for failed login
    if not user:
        log_security('LOGIN_FAILED',
                     details={'username': username, 'reason': 'user not found'},
                     severity='WARNING', ip=ip, ua=ua)
        #return this message but DONT say which one is wrong
        return False, 'Invalid username or password.'

    #check when this user is locked out until, if they are locked out then dont let them in
    if user.get('locked_until') and time.time() < user['locked_until']:
        remaining = int(user['locked_until'] - time.time())
        log_security('LOGIN_BLOCKED_LOCKED', user_id=username,
                     severity='WARNING', ip=ip, ua=ua)
        return False, f'Account locked. Try again in {remaining // 60}m {remaining % 60}s.'

    #bcrypt checking password
    #takes the password hash, takes the salt out and combines it with the entered password then compares the hash
    #if it matches then its ok
    if not bcrypt.checkpw(password.encode('utf-8'),
                          user['password_hash'].encode('utf-8')):
        #if it is not ok, then add to the failed attempts count
        user['failed_attempts'] = user.get('failed_attempts', 0) + 1
        #they get locked out for 15 min if they get the username right but password wrong 5 times
        if user['failed_attempts'] >= Config.MAX_FAILED_ATTEMPTS:
            #calculate what time they can try again
            user['locked_until'] = time.time() + Config.LOCKOUT_DURATION
            #reset their attempts
            user['failed_attempts'] = 0
            #update the users data
            save_user(user)
            #log the event of locking this person out
            log_security('ACCOUNT_LOCKED', user_id=username,
                         details={'reason': '5 failed attempts'},
                         severity='ERROR', ip=ip, ua=ua)
            return False, 'Account locked after too many failed attempts. Try again in 15 minutes.'
        save_user(user)
        #log the failed attempt
        log_security('LOGIN_FAILED', user_id=username,
                     details={'attempts': user['failed_attempts']},
                     severity='WARNING', ip=ip, ua=ua)
        return False, 'Invalid username or password.'

    #reset the timers and attempts after they successfully log in
    user['failed_attempts'] = 0
    user['locked_until'] = None
    #update the last login time with the current time
    user['last_login'] = time.time()
    save_user(user)

    #create a session with the user's name, ip, and browser/operating system
    token = session_manager.create(username, ip, ua)
    #log the event again
    log_security('LOGIN_SUCCESS', user_id=username, ip=ip, ua=ua)
    return True, token



def change_password(username: str, current_password: str,
                    new_password: str, confirm: str):
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '')
 
    user = get_user_by_username(username)
    if not user:
        return False, 'User not found.'
 
    # verify current password first
    if not bcrypt.checkpw(current_password.encode('utf-8'),
                          user['password_hash'].encode('utf-8')):
        log_security('PASSWORD_CHANGE_FAILED', user_id=username,
                     details={'reason': 'wrong current password'},
                     severity='WARNING', ip=ip, ua=ua)
        return False, 'Current password is incorrect.'
 
    # validate new password meets requirements
    error = validate_password(new_password)
    if error:
        return False, error
 
    # new password cannot be the same as current
    if bcrypt.checkpw(new_password.encode('utf-8'),
                      user['password_hash'].encode('utf-8')):
        return False, 'New password must be different from current password.'
 
    # confirm passwords match
    if new_password != confirm:
        return False, 'New passwords do not match.'
 
    # hash and save new password
    salt = bcrypt.gensalt(rounds=12)
    user['password_hash'] = bcrypt.hashpw(
        new_password.encode('utf-8'), salt).decode('utf-8')
    save_user(user)
 
    log_security('PASSWORD_CHANGED', user_id=username,
                 severity='INFO', ip=ip, ua=ua)
    return True, 'Password changed successfully.'

#ROLE BASED ACCESS CONTROL

def load_session_user():
    #get the session token from the browser request
    token = request.cookies.get('session_token')
    #checks does this token exist?
    session = session_manager.validate(token) if token else None
    #save the token into the current session
    g.session_token = token
    #find the username in the dictionary depending on the username in the session
    g.user = get_user_by_username(session['username']) if session else None

#wrapper that checks if g has a user value inside 
def require_auth(f):
    #go back to login if not authenticated
    @wraps(f)
    def wrapper(*args, **kwargs):
        #is there a value for user inside g?
        if not g.get('user'):
            #if theres nothing, then go back to login page
            return redirect('/login')
        #if there is, then execute the original function
        return f(*args, **kwargs)
    return wrapper

#receive the role from input
def require_role(*roles):
    #receive the function
    def decorator(f):
        #wrap the function
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = g.get('user')
            if not user:
                return redirect('/login')
            #use the function received in decorator
            #is the users role inside the roles input?
            if user['role'] not in roles:
                #log the access denied avent
                log_security('ACCESS_DENIED', user_id=user['username'],
                             details={'resource': request.path,
                                      'required_roles': list(roles),
                                      'user_role': user['role']},
                             severity='WARNING',
                             ip=request.remote_addr)
                #you are logged in but not allowed here!!!
                abort(403)
            #return function if success 
            return f(*args, **kwargs)
        return wrapper
    return decorator