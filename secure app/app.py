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

#creating flask application named app
app = Flask(__name__)
#using secret key from config (actually random number using secrets)
app.secret_key = Config.SECRET_KEY

#creating directories if they dont already exist
os.makedirs(Config.DATA_DIR, exist_ok=True)
os.makedirs(Config.LOGS_DIR, exist_ok=True)
os.makedirs(Config.UPLOADS_DIR, exist_ok=True)



#get the session token from browser, checks if it exists and if it is still valid, 
#loads the user and does this check each time a new page is visited
#sets g.user
@app.before_request
def load_user():
    #in auth.py
    load_session_user()

#after the route function (like /login, /dashboard, etc) is completed, do this method.
@app.after_request
def set_security_headers(response):
    #tells browsers what sources are allowed to load content
    #default-src 'self' means only load stuff from our server 
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        #avoiding unsafe inline in production
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    #prevent clickjacking 
    response.headers['X-Frame-Options'] = 'DENY'
    #prevent MIME type sniffing, stops browser from needing to guess file type
    response.headers['X-Content-Type-Options'] = 'nosniff'
    #XSS protection (legacy but still useful), tells older browsers to block pages if they detect XSS
    response.headers['X-XSS-Protection'] = '1; mode=block'
    #referrer policy, controls what url info is sent when clicking link
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    #permissions policy, disables unused browser features like geolocation, microphone, and camera
    response.headers['Permissions-Policy'] = (
        'geolocation=(), microphone=(), camera=()'
    )
    #hsts (strict transport security). Says to ALWAYS use HTTPS 
    response.headers['Strict-Transport-Security'] = (
        'max-age=31536000; includeSubDomains'
    )
    return response

#runs before route functions, FORCING HTTPS
#if the env is NOT development and NOT secure (not https)
@app.before_request
def enforce_https():
    if Config.ENV != 'development' and not request.is_secure:
        #replace the http part with https
        url = request.url.replace('http://', 'https://', 1)
        #redirect to that new url
        return redirect(url, code=301)

#runs after security headers are added and then logs who did what and what the result was
#also logs the http status code
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


#no permission
@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', code=403,
                           message='You do not have permission to access this page.'), 403

#page doesnt exist
@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404,
                           message='Page not found.'), 404

#some server error
@app.errorhandler(500)
def server_error(e):
    log_security('SERVER_ERROR', details={'error': str(e)},
                 severity='ERROR', ip=request.remote_addr)
    return render_template('error.html', code=500,
                           message='Something went wrong. Please try again later.'), 500



#redirects to login or dashboard depending on if there is a user inside g.user
@app.route('/')
def index():
    return redirect('/dashboard' if g.user else '/login')

#page to register and create an account with GET and POST methods
@app.route('/register', methods=['GET', 'POST'])
def register():
    #if there is a user loaded into g.user, then there is no reason to be at the register page, go to their dashboard
    if g.user:
        return redirect('/dashboard')
    error = None
    #skips over this the first time because first request is GET.
    #once it comes around a second time (the user entered a username and password then clicked submit), the method is POST
    #then runs these statements
    if request.method == 'POST':
        #pass all of the input from the received request from browser into the 
        #register user method which will sanitize and check if everything is valid
        ok, msg = register_user(
            request.form.get('username', ''),
            request.form.get('email', ''),
            request.form.get('password', ''),
            request.form.get('confirm_password', ''),
        )
        #if its ok, then show a message and redirect to the login page
        if ok:
            flash('Account created! Please log in.', 'success')
            return redirect('/login')
        error = msg
    #first time when browser sends GET (first visiting page), render this first with empty template
    #if successful account created, then it should go to login, but if not then render the template again with the error        
    return render_template('register.html', error=error)

#goes to page that allows user to login using their username and password. Also allows them to redirect to the register account page
@app.route('/login', methods=['GET', 'POST'])
def login():
    #same as above, no reason to be in the login page if the user is logged in.
    #if there is a user in g.user then go to their dashboard
    if g.user:
        return redirect('/dashboard')
    error = None
    #default GET again, skips over this the first time it loads (renders the template below), 
    #then when the user clicks a submit button, then it sends a POST
    if request.method == 'POST':
        #get the username and password from the received request and enters it into the login_user method
        ok, result = login_user(
            request.form.get('username', ''),
            request.form.get('password', ''),
        )
        if ok:
            #create an object so you can redirect with the cookie
            response = make_response(redirect('/dashboard'))
            response.set_cookie(
                'session_token', result,
                #only http can read token, no javascript
                httponly=True,                              
                #https only
                secure=(Config.ENV != 'development'),       
                #csrf protection
                samesite='Strict',     
                #max 30 min                    
                max_age=Config.SESSION_TIMEOUT,
            )
            return response
        error = result
    #first time visiting renders empty html page, shouldnt reach here if successful. if theres an error load this template again with error
    return render_template('login.html', error=error)

#logout route, only needs the post method since we dont need to see anything, just want flask to do something
@app.route('/logout', methods=['POST'])
def logout():
    #get the session token from the request
    token = request.cookies.get('session_token')
    #IMPORTANT, if it still exists afterward then if someone gets this token later,
    #they can use this token to log in as someone else without username or password.
    #if you get rid of it from the json (like this) then even if someone obtains the token,
    #it is still useless because the session DOES NOT EXIST, and does NOT allow someone to 
    #log in without username and password
    if token:
        session_manager.destroy(token)
    #create an object so you can redirect while destroying cookie
    response = make_response(redirect('/login'))
    response.delete_cookie('session_token')
    return response



#default to GET method and go to dashboard if there is a user
#using require_auth so it directs back to login if there is no g.user at the time
@app.route('/dashboard')
@require_auth
def dashboard():
    #pass in the name and role to get user documents
    #username is to see if it has been shared to them or if they are the owner
    #passing role in because if they are admin, then they should be able to see ALL of the documents
    docs = get_user_documents(g.user['username'], g.user['role'])
    #render template with variables (matching user in parameter to the variables in the html)
    return render_template('dashboard.html', user=g.user, documents=docs)

#upload a file, dont need to show anything so just POST method again.
#require auth to kick back to login page if not authenticated (no g.user)
@app.route('/documents/upload', methods=['POST'])
@require_auth
def upload():
    #guests cannot upload, probably shouldnt even be able to see upload button
    if g.user['role'] == 'guest':
        flash('Guests cannot upload files.', 'error')
        #go back to dashboard
        return redirect('/dashboard')
    #if there was no file in the request or if the file name is empty 
    if 'file' not in request.files or not request.files['file'].filename:
        flash('No file selected.', 'error')
        return redirect('/dashboard')
    #sanitize, check the size, replace old file (if has same name), encrypt, save the document, log the event
    #lot of stuff was moved from here to the documents.py file
    #request.files['file'] is the filename given in the request object
    ok, result = upload_document(
        request.files['file'], g.user['username'], request.remote_addr)
    #flash file uploaded and encrypted if "ok" is true and success, otherwise if ok is false then say error
    flash('File uploaded and encrypted.' if ok else result,
          'success' if ok else 'error')
    return redirect('/dashboard')

#just GET method
#
@app.route('/documents/<doc_id>/download')
@require_auth
def download(doc_id: str):
    #convert any "-" characters to nothing and checks if the input is ONLY letters and numbers (alphanumaric)
    #stops if the format is wrong at all and aborts. 
    #prevents users from trying to inject things into the url
    if not doc_id.replace('-', '').isalnum():
        abort(400)
    #return T/F, the decrypted bytes, and the files name after it calls download document
    #passes in the doc id, username, ip, and role
    ok, data, filename = download_document(
        doc_id, g.user['username'], request.remote_addr, g.user['role'])
    #if the download failed, then just flash an error and redirect instead of crashing
    if not ok:
        flash(data, 'error')
        return redirect('/dashboard')
    #if it succeeded the send the data
    #io.BytesIO wraps the decrypted bytes into a file like object 
    #download_name just tells the browser what to name the the file when saving instead of the uuid
    #as_attachment tells the browser to download the file and not to open it into the browser 
    return send_file(io.BytesIO(data), download_name=filename, as_attachment=True)

#just POST method because nothing to display, just do
@app.route('/documents/<doc_id>/share', methods=['POST'])
@require_auth
def share(doc_id: str):
    #guests cannot share, shouldnt even be able to get here
    if g.user['role'] == 'guest':
        flash('Guests cannot share files.', 'error')
        return redirect('/dashboard')
    #same thing as download,
    #convert any "-" characters to nothing and checks if the input is ONLY letters and numbers (alphanumaric)
    #stops if the format is wrong at all and aborts. 
    #prevents users from trying to inject things into the url    
    if not doc_id.replace('-', '').isalnum():
        abort(400)
    #cleans up the username with html.escape (function in auth.py)
    target = sanitize(request.form.get('username', ''))
    #gets the selected role from the request of "viewer" or "editor" though they dont actually change anything that they can do
    role = request.form.get('role', 'viewer')
    #call share documents with these parameters because:
    #doc_id: which document
    #g.user['username']: which user is sharing?
    #target is who they want to share with
    #role is what role they are getting (viewer/editor)
    #ip for logging
    #g.user['role'] in case the user is admin, so the admin can also share any file
    ok, msg = share_document(doc_id, g.user['username'], target, role,
                              request.remote_addr, g.user['role'])
    flash(msg, 'success' if ok else 'error')
    return redirect('/dashboard')


@app.route('/documents/<doc_id>/delete', methods=['POST'])
@require_auth
def delete_doc(doc_id: str):
    #same thing as download,
    #convert any "-" characters to nothing and checks if the input is ONLY letters and numbers (alphanumaric)
    #stops if the format is wrong at all and aborts. 
    #prevents users from trying to inject things into the url  
    if not doc_id.replace('-', '').isalnum():
        abort(400)
    #pass into delete_document
    #doc_id for what doc
    #g.user['username'] to check is this the owner of the doc
    #remote_addr for ip for logging
    #g.user['role'] to see if they are admin because admin can delete any doc
    ok, msg = delete_document(doc_id, g.user['username'],
                               request.remote_addr, g.user['role'])
    flash(msg, 'success' if ok else 'error')
    return redirect('/dashboard')

#GET POST because need to display and submit stuff
@app.route('/profile/change-password', methods=['GET', 'POST'])
@require_auth
def change_password_route():
    #error is initially none
    error = None
    #skips when user first opens page
    #once the user submits (sends a request with POST), then run this stuff
    if request.method == 'POST':
        #pass info from the request into the change_password
        ok, msg = change_password(
            g.user['username'],
            request.form.get('current_password', ''),
            request.form.get('new_password', ''),
            request.form.get('confirm_password', ''),
        )
        #if change_password was successful, then destroy any sessions for this user that are still active
        if ok:
            from session_manager import session_manager
            session_manager.destroy_all_for_user(g.user['username'])
            #once again create and object so you can redirect while deleting the cookie
            response = make_response(redirect('/login'))
            response.delete_cookie('session_token')
            flash('Password changed. Please log in again.', 'success')
            return response
        error = msg
    #renders the template 
    #its empty on first GET request, and if it reaches here during the POST, then display the error message of why it failed
    return render_template('change_password.html', user=g.user, error=error)
 



#just GET method, require authentication (needs to be logged in), and MUST be admin. 
#calls admin_dashboard() when someone visits /admin 
@app.route('/admin')
@require_auth
@require_role('admin')
def admin_dashboard():
    #renders the admin html template and passes two variables user=g.user and user=load_users()
    return render_template('admin.html', user=g.user, users=load_users())

#only POST since this is just a form. requires user to be logged in AND have admin role
@app.route('/admin/users/<username>/role', methods=['POST'])
@require_auth
@require_role('admin')
def change_role(username: str):
    #runs the html.escape() on the username from the url to prevent any injection attempts
    username = sanitize(username)
    #getting the selected role from the dropdown form. this defaults to user if nothing is selected
    new_role = request.form.get('role', 'user')
    #whitelist check to see if someone tried to make some new role
    if new_role not in ('admin', 'user', 'guest'):
        #flash an error and go back to the admin dashboard
        flash('Invalid role.', 'error')
        return redirect('/admin')
    #look up the account being changed inside users.json
    target = get_user_by_username(username)
    #if the username doesnt exist in the dictionary then flash an error and go back to the admin page
    if not target:
        flash('User not found.', 'error')
        return redirect('/admin')
    #just makes sure that the admin (yourself) cant change their own role and accidentally lock themselves out
    if username == g.user['username']:
        flash('You cannot change your own role.', 'error')
        return redirect('/admin')
    #updates the targets role
    target['role'] = new_role
    #saves the updated user info back to users.json
    save_user(target)

    #if downgraded to guest, restrict all document permissions to viewer
    #guests should be READ ONLY!
    if new_role == 'guest':
        #loading all documents from load_documents
        docs = load_documents()
        #check if any documents were changed or not 
        changed = False
        #loop through all docs 
        for doc in docs.values():
            #check if the document was shared with this user
            if username in doc.get('shared_with', {}):
                #change their role to viewer on the document
                doc['shared_with'][username] = 'viewer'
                #something was changed, change this to be true
                changed = True
        #since it was changed, we need to update it in the documents json
        if changed:
            save_documents(docs)
    #log the role change. this logs who made the change, what account was changed, and what the new role is
    log_security('ROLE_CHANGED', user_id=g.user['username'],
                 details={'target': username, 'new_role': new_role},
                 ip=request.remote_addr)
    #flash a successful message
    flash(f'Role updated for {username}.', 'success')
    return redirect('/admin')


if __name__ == '__main__':
    #no ssl context by default 
    ssl_ctx = None
    #checks if both cert.pem and key.pem actually exist before trying to use them
    if os.path.exists(Config.SSL_CERT) and os.path.exists(Config.SSL_KEY):
        #if both files exist, then create a tuple that has both paths to the files
        #flask then accepts this as an ssl context, telling it where to find the certificate and private key
        ssl_ctx = (Config.SSL_CERT, Config.SSL_KEY)
    #starts flask development server with debug OFF
    #pass the ssl context into flask. if ssl context is none, then run without https
    #host 0.0.0.0 tells flask to listen on all network interfaces and not just the local host (allows other devices to access)
    #port 5000 runs the app on port 5000
    app.run(debug=False,  # debug OFF in week 3+
            ssl_context=ssl_ctx,
            host='0.0.0.0',
            port=5000)