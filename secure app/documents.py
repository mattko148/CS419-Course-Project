"""
documents.py — Hardened in week 3.
Adds on top of the basic upload/download from week 2:
  - Fernet encryption of every file before saving to disk
  - Decryption on download
  - Proper access control checks (owner / shared_with roles)
  - Path traversal prevention via secure_filename + abspath check
  - File extension whitelist + size limit
"""
import os
import uuid
import time
from werkzeug.utils import secure_filename

from config import Config
from models import get_document, save_document, load_documents, save_documents
from encryption import encryption
from logger import log_security

#get the allowed extensions from the config file
ALLOWED_EXTENSIONS = Config.ALLOWED_EXTENSIONS

#checking if the filenames extension is allowed (private function)
def _safe_ext(filename: str):
    #split the filename into 2 parts from the right
    parts = filename.rsplit('.', 1)
    #check if the extension is in the allowed list
    #the len == 2 part checks if there was even a period (.) inside
    if len(parts) == 2 and parts[1].lower() in ALLOWED_EXTENSIONS:
        #if it is, then return the extension in lowercase
        return parts[1].lower()
    return None

#finds what roles the given user has with the given document (dictionary)
def _user_role(doc: dict, username: str):
    #if its the owner, then just return owner
    if doc['owner'] == username:
        return 'owner'
    #if its not the owner, just go to the documents shared with entry and then find the users name inside that entry, then return their role
    #because the format would be like "bob": "guest"
    return doc.get('shared_with', {}).get(username)


def upload_document(file_storage, owner: str, ip: str):
    #sanitize the filename
    filename = secure_filename(file_storage.filename)
    #if theres nothing left after sanitizing, that means the entire thing was dangerous
    if not filename:
        return False, 'Invalid filename.'

    #check the extension to see if it is in the allowed list
    ext = _safe_ext(filename)
    #if its not, then reject it and log the failed file type event
    if not ext:
        log_security('INVALID_FILE_TYPE', user_id=owner,
                     details={'filename': filename}, severity='WARNING', ip=ip)
        return False, f'File type not allowed. Allowed: {", ".join(sorted(ALLOWED_EXTENSIONS))}'

    #read the MAX_UPLOAD_BYTES + 1
    #this is because if it tries to read the max upload + 1, then we already know that the 
    #file sent is BIGGER than the max file
    #dont know how much, dont care because it is bigger than max
    #shouldnt read the entire file and should just stop as soon as we know its bigger than the max
    #because if the user sent a HUGE file, it would need to read all of it to know its too big, when we dont need to read the entire thing to know
    raw = file_storage.read(Config.MAX_UPLOAD_BYTES + 1)
    if len(raw) > Config.MAX_UPLOAD_BYTES:
        return False, 'File too large (max 10 MB).'


    #ENCRYPT THE BYTES! DATA AT REST
    encrypted = encryption.encrypt(raw)

    #make an upload directory if it isnt there already
    os.makedirs(Config.UPLOADS_DIR, exist_ok=True)

# Check if this owner already has a file with the same name
    # If so, replace it instead of creating a duplicate
    existing_doc = None
    for doc in load_documents().values():
        if doc['original_name'] == filename and doc['owner'] == owner:
            existing_doc = doc
            break

    if existing_doc:
        # delete the old encrypted file from disk
        for v in existing_doc.get('versions', []):
            try:
                os.remove(v['stored_path'])
            except FileNotFoundError:
                pass

        # save new encrypted file using the same doc_id
        doc_id = existing_doc['id']
        stored_path = os.path.join(Config.UPLOADS_DIR, doc_id + '.enc')

        # path traversal check
        base = os.path.abspath(Config.UPLOADS_DIR)
        full = os.path.abspath(stored_path)
        if not full.startswith(base):
            log_security('PATH_TRAVERSAL', user_id=owner, severity='CRITICAL', ip=ip)
            return False, 'Invalid file path.'

        with open(stored_path, 'wb') as f:
            f.write(encrypted)

        # update the existing document entry with new version
        new_version = existing_doc['current_version'] + 1
        existing_doc['versions'].append({
            'version': new_version,
            'created_at': time.time(),
            'stored_path': stored_path,
        })
        existing_doc['current_version'] = new_version
        save_document(existing_doc)

        log_security('DOCUMENT_REPLACED', user_id=owner,
                     details={'doc_id': doc_id, 'filename': filename,
                              'version': new_version}, ip=ip)
        return True, doc_id

    #there is not already a file, so create a new one
    doc_id = str(uuid.uuid4())
    #joins the intended path, doc id, and .enc
    stored_path = os.path.join(Config.UPLOADS_DIR, doc_id + '.enc')

    #the absolute path to the directory
    #this would be data/uploads, so it would add the absolute path of our current directory to this
    base = os.path.abspath(Config.UPLOADS_DIR)
    #strips away any dangerous path names like ../../ or whatever to navigate through directories and combines
    #stored path with absolute path of running directory
    full = os.path.abspath(stored_path)

    #if the "full" does not start with the base, then some path traversal was attempted
    if not full.startswith(base):
        #log the event and return false
        log_security('PATH_TRAVERSAL', user_id=owner, severity='CRITICAL', ip=ip)
        return False, 'Invalid file path.'

    #write the bytes into a file
    with open(stored_path, 'wb') as f:
        f.write(encrypted)

    #save the document data into documents.json
    save_document({
        'id': doc_id,
        'original_name': filename,
        'extension': ext,
        'owner': owner,
        'shared_with': {},
        'created_at': time.time(),
        'versions': [{'version': 1, 'created_at': time.time(),
                      'stored_path': stored_path}],
        'current_version': 1,
    })

    #log the event that it was successfully uploaded
    log_security('DOCUMENT_UPLOADED', user_id=owner,
                 details={'doc_id': doc_id, 'filename': filename}, ip=ip)
    return True, doc_id


def download_document(doc_id: str, username: str, ip: str, role: str = 'user'):
    #get the document
    doc = get_document(doc_id)
    #if there is nothing with this id, then return error
    if not doc:
        return False, 'Document not found.', ''

    #admin can download whatever, so just skip this
    if role == 'admin':
        pass
    #guests can only download documents that are shared with them
    elif role == 'guest':
        #if the user is not in the dictionary of shared with, then return an error 
        if username not in doc.get('shared_with', {}):
            #log the event that the user did not have access/was not in shared with
            log_security('ACCESS_DENIED', user_id=username,
                         details={'doc_id': doc_id, 'action': 'download',
                                  'reason': 'guest not in shared_with'},
                         severity='WARNING', ip=ip)
            return False, 'Access denied.', ''
    # user can download own files or shared files
    else:
        #checks if this user has any relation to this document
        #it could return owner or guest or none. If its owner or guest, then its ok, otherwise deny
        if not _user_role(doc, username):
            #log the access denied download attempt
            log_security('ACCESS_DENIED', user_id=username,
                         details={'doc_id': doc_id, 'action': 'download'},
                         severity='WARNING', ip=ip)
            return False, 'Access denied.', ''

    #get the most recent version of the document and reads it
    stored_path = doc['versions'][-1]['stored_path']
    with open(stored_path, 'rb') as f:
        encrypted = f.read()

    #decrypt the data
    data = encryption.decrypt(encrypted)
    #log the download event
    log_security('DOCUMENT_DOWNLOADED', user_id=username,
                 details={'doc_id': doc_id}, ip=ip)
    #return true, doc name, and data
    return True, data, doc['original_name']


def share_document(doc_id: str, owner: str,
                   target_user: str, role: str, ip: str,
                   user_role: str = 'user'):
    
    #get the document
    doc = get_document(doc_id)
    #if theres nothing, there was an error
    if not doc:
        return False, 'Document not found.'
    #if you arent the owner of the doc, then you cant share it
    if doc['owner'] != owner and user_role != 'admin':
        #log the failed sharing attempt
        log_security('SHARE_DENIED', user_id=owner,
                     details={'doc_id': doc_id}, severity='WARNING', ip=ip)
        return False, 'Only the owner can share this document.'
    #if your role is not view or editor, then you cant share either (aka if you are guest)
    if role not in ('viewer', 'editor'):
        return False, 'Role must be viewer or editor.'

    #get the doc, go to the shared with dictionary, inside go to the user, and set their role to the given role in parameter
    doc['shared_with'][target_user] = role
    #save updated doc with permission
    save_document(doc)
    #log successful sharing of the document
    log_security('DOCUMENT_SHARED', user_id=owner,
                 details={'doc_id': doc_id, 'target': target_user,
                          'role': role}, ip=ip)
    return True, f'Shared with {target_user} as {role}.'


def delete_document(doc_id: str, username: str, ip: str,
                    user_role: str = 'user'):
    #get the doc
    doc = get_document(doc_id)
    #if theres nothing, error 
    if not doc:
        return False, 'Document not found.'
    #if you arent the owner, then you cant delete the document
    if doc['owner'] != username and user_role != 'admin':
        #log the failed deletion event
        log_security('DELETE_DENIED', user_id=username,
                     details={'doc_id': doc_id}, severity='WARNING', ip=ip)
        return False, 'Only the owner can delete this document.'

    #delete each file version
    for v in doc.get('versions', []):
        #if its already gone, dont crash just move on
        try:
            os.remove(v['stored_path'])
        except FileNotFoundError:
            pass

    #load the documents
    docs = load_documents()
    #pop it out of dictionary
    docs.pop(doc_id, None)
    #save updated dictionary
    save_documents(docs)

    #log the successful deletion of the document
    log_security('DOCUMENT_DELETED', user_id=username,
                 details={'doc_id': doc_id}, ip=ip)
    return True, 'Document deleted.'