import os
import uuid
import time
import io
from flask import (Flask, g, request, redirect, render_template,
                   make_response, flash, send_file)
from werkzeug.utils import secure_filename

from config import Config
from models import (get_user_by_username, get_user_by_email, save_user,
                    load_sessions, save_sessions, get_user_documents,
                    get_document, save_document, load_documents, save_documents)

app = Flask(__name__)
app.secret_key = Config.SECRET_KEY

#creating directories if they dont already exist
os.makedirs(Config.DATA_DIR, exist_ok=True)
os.makedirs(Config.LOGS_DIR, exist_ok=True)
os.makedirs(Config.UPLOADS_DIR, exist_ok=True)

ALLOWED_EXTENSIONS = {'pdf', 'txt', 'docx', 'png', 'jpg', 'jpeg'}


#session functions

#creatign a random token to identify session and recording user information under it, then 
#returning the token
def create_session(username: str) -> str:
    token = str(uuid.uuid4())  # TODO week 3: replace with secrets.token_urlsafe
    sessions = load_sessions()
    sessions[token] = {
        'username': username,
        'created_at': time.time(),
    }
    save_sessions(sessions)
    return token

#checking is this session valid?
#if it is then who is holding this session?
def get_session_user(token: str):
    if not token:
        return None
    sessions = load_sessions()
    session = sessions.get(token)
    if not session:
        return None
    return get_user_by_username(session['username'])


# ---------------------------------------------------------------------------
# Load current user before every request
# ---------------------------------------------------------------------------

@app.before_request
def load_user():
    token = request.cookies.get('session_token')
    g.user = get_session_user(token)
    g.session_token = token


# ---------------------------------------------------------------------------
# Routes — Auth
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    if g.user:
        return redirect('/dashboard')
    return redirect('/login')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if g.user:
        return redirect('/dashboard')
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        # Basic validation (no security hardening yet)
        if not username or not email or not password:
            error = 'All fields are required.'
        elif password != confirm:
            error = 'Passwords do not match.'
        elif get_user_by_username(username):
            error = 'Username already taken.'
        elif get_user_by_email(email):
            error = 'Email already registered.'
        else:
            # TODO week 3: hash password with bcrypt
            save_user({
                'username': username,
                'email': email,
                'password': password,  # plaintext — will be fixed in week 3
                'role': 'user',
                'created_at': time.time(),
            })
            flash('Account created! Please log in.', 'success')
            return redirect('/login')

    return render_template('register.html', error=error)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user:
        return redirect('/dashboard')
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = get_user_by_username(username)

        # TODO week 3: use bcrypt.checkpw, add lockout and rate limiting
        if not user or user['password'] != password:
            error = 'Invalid username or password.'
        else:
            token = create_session(username)
            response = make_response(redirect('/dashboard'))
            # TODO week 3: add httponly, secure, samesite flags
            response.set_cookie('session_token', token)
            return response

    return render_template('login.html', error=error)


@app.route('/logout', methods=['POST'])
def logout():
    token = request.cookies.get('session_token')
    if token:
        sessions = load_sessions()
        sessions.pop(token, None)
        save_sessions(sessions)
    response = make_response(redirect('/login'))
    response.delete_cookie('session_token')
    return response


# ---------------------------------------------------------------------------
# Routes — Dashboard
# ---------------------------------------------------------------------------

@app.route('/dashboard')
def dashboard():
    # TODO week 3: replace with @require_auth decorator
    if not g.user:
        return redirect('/login')
    docs = get_user_documents(g.user['username'])
    return render_template('dashboard.html', user=g.user, documents=docs)


# ---------------------------------------------------------------------------
# Routes — Documents
# ---------------------------------------------------------------------------

@app.route('/documents/upload', methods=['POST'])
def upload():
    if not g.user:
        return redirect('/login')

    if 'file' not in request.files:
        flash('No file selected.', 'error')
        return redirect('/dashboard')

    f = request.files['file']
    if not f.filename:
        flash('No file selected.', 'error')
        return redirect('/dashboard')

    filename = secure_filename(f.filename)
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''

    if ext not in ALLOWED_EXTENSIONS:
        flash(f'File type not allowed.', 'error')
        return redirect('/dashboard')

    # Save file as-is (TODO week 3: encrypt with Fernet before saving)
    doc_id = str(uuid.uuid4())
    stored_path = os.path.join(Config.UPLOADS_DIR, doc_id + '_' + filename)
    f.save(stored_path)

    save_document({
        'id': doc_id,
        'original_name': filename,
        'extension': ext,
        'owner': g.user['username'],
        'shared_with': {},
        'created_at': time.time(),
        'stored_path': stored_path,
    })

    flash('File uploaded successfully.', 'success')
    return redirect('/dashboard')


@app.route('/documents/<doc_id>/download')
def download(doc_id: str):
    if not g.user:
        return redirect('/login')

    doc = get_document(doc_id)
    if not doc:
        flash('Document not found.', 'error')
        return redirect('/dashboard')

    # TODO week 3: check access permissions properly
    if doc['owner'] != g.user['username'] and \
       g.user['username'] not in doc.get('shared_with', {}):
        flash('Access denied.', 'error')
        return redirect('/dashboard')

    # TODO week 3: decrypt file before sending
    with open(doc['stored_path'], 'rb') as file:
        data = file.read()

    return send_file(
        io.BytesIO(data),
        download_name=doc['original_name'],
        as_attachment=True,
    )


@app.route('/documents/<doc_id>/share', methods=['POST'])
def share(doc_id: str):
    if not g.user:
        return redirect('/login')

    doc = get_document(doc_id)
    if not doc or doc['owner'] != g.user['username']:
        flash('Access denied.', 'error')
        return redirect('/dashboard')

    target = request.form.get('username', '').strip()
    role = request.form.get('role', 'viewer')

    if not get_user_by_username(target):
        flash('User not found.', 'error')
        return redirect('/dashboard')

    doc['shared_with'][target] = role
    save_document(doc)
    flash(f'Shared with {target} as {role}.', 'success')
    return redirect('/dashboard')


@app.route('/documents/<doc_id>/delete', methods=['POST'])
def delete_doc(doc_id: str):
    if not g.user:
        return redirect('/login')

    doc = get_document(doc_id)
    if not doc or doc['owner'] != g.user['username']:
        flash('Access denied.', 'error')
        return redirect('/dashboard')

    # Remove stored file
    try:
        os.remove(doc['stored_path'])
    except FileNotFoundError:
        pass

    docs = load_documents()
    docs.pop(doc_id, None)
    save_documents(docs)

    flash('Document deleted.', 'success')
    return redirect('/dashboard')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)