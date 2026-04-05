import json
import os
from config import Config
import time

#check if the path exists. If it doesnt then return an empty dictionary, otherwise open the json file
#and return it
def _load(path: str):
    """Load JSON from file, return empty dict if missing."""
    if not os.path.exists(path):
        return {}
    with open(path, 'r') as f:
        return json.load(f)

#make the directory with the name of str if it doesnt exist, then dump the data into the file
def _save(path: str, data) -> None:
    """Write JSON to file."""
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)


#users functions
#go to config and get the user file path
def load_users() -> dict:
    return _load(Config.USERS_FILE)

#go to config and update the old user dictionary with new one
def save_users(users: dict) -> None:
    _save(Config.USERS_FILE, users)

#using the dictionary returned by load users, get the user with the username
def get_user_by_username(username: str):
    return load_users().get(username)

#use the dictionary and iterate through the dictionary to find which user has the specific email
def get_user_by_email(email: str):
    for user in load_users().values():
        if user.get('email', '').lower() == email.lower():
            return user
    return None

#get the user dictionary, add the new user into it, then save this update dictionary
def save_user(user: dict) -> None:
    users = load_users()
    users[user['username']] = user
    save_users(users)


#session functions
#go to configs and get the json file
def load_sessions() -> dict:
    return _load(Config.SESSIONS_FILE)

#with this sessions dictionary, update the sessions file with this new update sessions.
def save_sessions(sessions: dict) -> None:
    _save(Config.SESSIONS_FILE, sessions)


#document functions
#go to config and return the documents json file
def load_documents() -> dict:
    return _load(Config.DOCUMENTS_FILE)

#save the new docs dictionary into json file
def save_documents(docs: dict) -> None:
    _save(Config.DOCUMENTS_FILE, docs)

#load the documents and get the id from the dictionary
def get_document(doc_id: str):
    return load_documents().get(doc_id)

#using the document's own id, update only this document in the docs 
def save_document(doc: dict) -> None:
    docs = load_documents()
    docs[doc['id']] = doc
    save_documents(docs)

#load the documents, create a list, and for every document this user is a part of
#whether it is owner or a person the doc is shared with, then add it to result and return this list
def get_user_documents(username: str, role: str = 'user') -> list:
    """Return all docs owned by or shared with a user."""
    docs = load_documents()


    #admin sees every document regardless of ownership or sharing
    if role == 'admin':
        return list(docs.values())

    #user and guest only see documents they own or that were shared with them
    result = []
    for doc in docs.values():
        if doc['owner'] == username:
            result.append(doc)
        elif username in doc.get('shared_with', {}):
            result.append(doc)
    return result

#rate limiting
_rate_store: dict = {}


def check_rate_limit(ip: str,
                     window: int = Config.RATE_LIMIT_WINDOW,
                     max_attempts: int = Config.RATE_LIMIT_ATTEMPTS) -> bool:
    """Return True if IP is within limit, False if exceeded."""
    now = time.time()
    attempts = _rate_store.get(ip, [])
    attempts = [t for t in attempts if now - t < window]
    _rate_store[ip] = attempts
    if len(attempts) >= max_attempts:
        return False
    attempts.append(now)
    _rate_store[ip] = attempts
    return True