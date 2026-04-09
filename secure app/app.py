"""
app.py — Security hardening added in weeks 3–4.
Changes from week 2:
  - load_session_user() replaces inline get_session_user()
  - @require_auth / @require_role decorators replace manual if-not-user checks
  - Secure cookie flags: httponly, secure, samesite
  - Generic error handlers (no internal details leaked to user)
  - Admin dashboard and role management routes added
  - doc_id format validated before use
  - Input sanitized with sanitize() before processing
  - Role-based access control: guests cannot upload or share
  - Admin sees all documents regardless of ownership
  - Role downgrade to guest automatically restricts document permissions
Week 5 will add: security headers, HTTPS redirect, access logging
"""
import os
import io
from flask import (Flask, g, request, redirect, render_template,
                   make_response, abort, send_file, flash)

from config import Config
from auth import (register_user, login_user, load_session_user,
                  require_auth, require_role, sanitize, change_password)
from session_manager import session_manager
from models import (get_user_by_username, load_users,
                    save_user, get_user_documents,
                    load_documents, save_documents)
from documents import (upload_document, download_document,
                       share_document, delete_document)
from logger import log_security, log_access

app = Flask(__name__)
app.secret_key = Config.SECRET_KEY

os.makedirs(Config.DATA_DIR, exist_ok=True)
os.makedirs(Config.LOGS_DIR, exist_ok=True)
os.makedirs(Config.UPLOADS_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# Load session user before every request (replaces week 2 inline logic)
# ---------------------------------------------------------------------------

@app.before_request
def load_user():
    load_session_user()


@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = (
        'geolocation=(), microphone=(), camera=()'
    )
    response.headers['Strict-Transport-Security'] = (
        'max-age=31536000; includeSubDomains'
    )
    return response


@app.before_request
def enforce_https():
    if Config.ENV != 'development' and not request.is_secure:
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)


@app.after_request
def access_log(response):
    log_access(
        method=request.method,
        path=request.path,
        status=response.status_code,
        user_id=g.user['username'] if g.get('user') else None,
        ip=request.remote_addr,
    )
    return response


# ---------------------------------------------------------------------------
# Generic error handlers — never leak internal details to the user
# ---------------------------------------------------------------------------

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', code=403,
                           message='You do not have permission to access this page.'), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404,
                           message='Page not found.'), 404


@app.errorhandler(500)
def server_error(e):
    log_security('SERVER_ERROR', details={'error': str(e)},
                 severity='ERROR', ip=request.remote_addr)
    return render_template('error.html', code=500,
                           message='Something went wrong. Please try again later.'), 500


# ---------------------------------------------------------------------------
# Public routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    return redirect('/dashboard' if g.user else '/login')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if g.user:
        return redirect('/dashboard')
    error = None
    if request.method == 'POST':
        ok, msg = register_user(
            request.form.get('username', ''),
            request.form.get('email', ''),
            request.form.get('password', ''),
            request.form.get('confirm_password', ''),
        )
        if ok:
            flash('Account created! Please log in.', 'success')
            return redirect('/login')
        error = msg
    return render_template('register.html', error=error)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user:
        return redirect('/dashboard')
    error = None
    if request.method == 'POST':
        ok, result = login_user(
            request.form.get('username', ''),
            request.form.get('password', ''),
        )
        if ok:
            response = make_response(redirect('/dashboard'))
            response.set_cookie(
                'session_token', result,
                httponly=True,                              # week 3: JS cannot read token
                secure=(Config.ENV != 'development'),       # week 3: HTTPS only
                samesite='Strict',                         # week 3: CSRF protection
                max_age=Config.SESSION_TIMEOUT,
            )
            return response
        error = result
    return render_template('login.html', error=error)


@app.route('/logout', methods=['POST'])
def logout():
    token = request.cookies.get('session_token')
    if token:
        session_manager.destroy(token)
    response = make_response(redirect('/login'))
    response.delete_cookie('session_token')
    return response


# ---------------------------------------------------------------------------
# Authenticated routes — now use @require_auth instead of manual checks
# ---------------------------------------------------------------------------

@app.route('/dashboard')
@require_auth
def dashboard():
    # pass role so admin sees all documents, others see only own/shared
    docs = get_user_documents(g.user['username'], g.user['role'])
    return render_template('dashboard.html', user=g.user, documents=docs)


@app.route('/documents/upload', methods=['POST'])
@require_auth
def upload():
    # guests cannot upload
    if g.user['role'] == 'guest':
        flash('Guests cannot upload files.', 'error')
        return redirect('/dashboard')
    if 'file' not in request.files or not request.files['file'].filename:
        flash('No file selected.', 'error')
        return redirect('/dashboard')
    ok, result = upload_document(
        request.files['file'], g.user['username'], request.remote_addr)
    flash('File uploaded and encrypted.' if ok else result,
          'success' if ok else 'error')
    return redirect('/dashboard')


@app.route('/documents/<doc_id>/download')
@require_auth
def download(doc_id: str):
    if not doc_id.replace('-', '').isalnum():
        abort(400)
    ok, data, filename = download_document(
        doc_id, g.user['username'], request.remote_addr, g.user['role'])
    if not ok:
        flash(data, 'error')
        return redirect('/dashboard')
    return send_file(io.BytesIO(data), download_name=filename, as_attachment=True)


@app.route('/documents/<doc_id>/share', methods=['POST'])
@require_auth
def share(doc_id: str):
    # guests cannot share
    if g.user['role'] == 'guest':
        flash('Guests cannot share files.', 'error')
        return redirect('/dashboard')
    if not doc_id.replace('-', '').isalnum():
        abort(400)
    target = sanitize(request.form.get('username', ''))
    role = request.form.get('role', 'viewer')
    ok, msg = share_document(doc_id, g.user['username'], target, role,
                              request.remote_addr, g.user['role'])
    flash(msg, 'success' if ok else 'error')
    return redirect('/dashboard')


@app.route('/documents/<doc_id>/delete', methods=['POST'])
@require_auth
def delete_doc(doc_id: str):
    if not doc_id.replace('-', '').isalnum():
        abort(400)
    ok, msg = delete_document(doc_id, g.user['username'],
                               request.remote_addr, g.user['role'])
    flash(msg, 'success' if ok else 'error')
    return redirect('/dashboard')


@app.route('/profile/change-password', methods=['GET', 'POST'])
@require_auth
def change_password_route():
    error = None
    if request.method == 'POST':
        ok, msg = change_password(
            g.user['username'],
            request.form.get('current_password', ''),
            request.form.get('new_password', ''),
            request.form.get('confirm_password', ''),
        )
        if ok:
            # destroy all sessions so user must log back in
            from session_manager import session_manager
            session_manager.destroy_all_for_user(g.user['username'])
            response = make_response(redirect('/login'))
            response.delete_cookie('session_token')
            flash('Password changed. Please log in again.', 'success')
            return response
        error = msg
    return render_template('change_password.html', user=g.user, error=error)
 


# ---------------------------------------------------------------------------
# Admin routes — added week 3 with @require_role
# ---------------------------------------------------------------------------

@app.route('/admin')
@require_auth
@require_role('admin')
def admin_dashboard():
    return render_template('admin.html', user=g.user, users=load_users())


@app.route('/admin/users/<username>/role', methods=['POST'])
@require_auth
@require_role('admin')
def change_role(username: str):
    username = sanitize(username)
    new_role = request.form.get('role', 'user')
    if new_role not in ('admin', 'user', 'guest'):
        flash('Invalid role.', 'error')
        return redirect('/admin')
    target = get_user_by_username(username)
    if not target:
        flash('User not found.', 'error')
        return redirect('/admin')
    if username == g.user['username']:
        flash('You cannot change your own role.', 'error')
        return redirect('/admin')
    target['role'] = new_role
    save_user(target)

    # if downgraded to guest, restrict all document permissions to viewer
    # per Piazza: guests should only be able to download (read-only)
    if new_role == 'guest':
        docs = load_documents()
        changed = False
        for doc in docs.values():
            if username in doc.get('shared_with', {}):
                doc['shared_with'][username] = 'viewer'
                changed = True
        if changed:
            save_documents(docs)

    log_security('ROLE_CHANGED', user_id=g.user['username'],
                 details={'target': username, 'new_role': new_role},
                 ip=request.remote_addr)
    flash(f'Role updated for {username}.', 'success')
    return redirect('/admin')


if __name__ == '__main__':
    ssl_ctx = None
    if os.path.exists(Config.SSL_CERT) and os.path.exists(Config.SSL_KEY):
        ssl_ctx = (Config.SSL_CERT, Config.SSL_KEY)
    app.run(debug=False,  # debug OFF in week 3+
            ssl_context=ssl_ctx,
            host='0.0.0.0',
            port=5000)