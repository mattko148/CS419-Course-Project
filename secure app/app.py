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

#which type of files are allowed
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
    #returning the json file
    sessions = load_sessions()
    #in the json file, find the token
    session = sessions.get(token)
    #if its not in there, then return none
    if not session:
        return None
    return get_user_by_username(session['username'])


#requests cookies to get the session token (if there is one), then uses it to find out who is logged in
#and sets the current user
#do this for every time the user redirects to another page

@app.before_request
def load_user():
    token = request.cookies.get('session_token')
    g.user = get_session_user(token)
    g.session_token = token


#home page, when going here, then it either goes to the users dashboard if they are logged in,
#otherwise send them back to the login

@app.route('/')
def index():
    if g.user:
        return redirect('/dashboard')
    return redirect('/login')


#page to register and create an account with GET and POST methods
@app.route('/register', methods=['GET', 'POST'])
def register():

    #saying "if youre logged in, what are you doing here? GO TO YOUR DASHBOARD"
    if g.user:
        return redirect('/dashboard')
    error = None

    #the method is default GET when visiting the page (when clicking in from /login), then when the user
    #presses "Create account", then the browser sends the entered user
    #and password to flask and the method is set to POST   
    if request.method == 'POST':
        #from the request package, inside the form get these inputs and get rid of whitespaces
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
            #go to login page once account is created
            return redirect('/login')
    #when first visiting the page, it goes past the if statement above and comes down here and 
    #renders the template first. The second time it comes around with the inputs from html.
    return render_template('register.html', error=error)

#go to the page that lets a user log in with a username and password, or redirect to a 
#page that lets them register a new account with GET and POST methods
@app.route('/login', methods=['GET', 'POST'])
def login():
    #saying "WHY ARE YOU HERE IF YOURE LOGGED IN, GO TO YOUR DASHBOARD"
    if g.user:
        return redirect('/dashboard')
    error = None
    #default GET again, skips over this the first time it loads (renders the template below), 
    #then when the user clicks a submit button, then it sends a POST
    if request.method == 'POST':
        #gets the username and password from the POST package
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        #use the entered username to find the user in the users json to compare password
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

    #render the template the first time this page loads with GET 
    return render_template('login.html', error=error)

#logout, only needs POST because this doesnt need to show any form, just do stuff
@app.route('/logout', methods=['POST'])
def logout():

    #find the session token to figure out who is sending this logout request
    #gets the token
    token = request.cookies.get('session_token')
    if token:
        #load the existing sessions
        sessions = load_sessions()
        #take the token out with the user, finds who has this token and pops out of dictionary
        #gets rid of the users name and token(with user and password) out of dictionary

        #IMPORTANT, if it still exists afterward then if someone gets this token later,
        #they can use this token to log in as someone else without username or password.
        #if you get rid of it from the json (like this) then even if someone obtains the token,
        #it is still useless because the session DOES NOT EXIST, and does NOT allow someone to 
        #log in without username and password
        sessions.pop(token, None)
        #save this updated directory back
        save_sessions(sessions)
    #create an object to redirect
    response = make_response(redirect('/login'))
    #putting instruction to delete the session token from browser
    response.delete_cookie('session_token')
    #sends this to browser which deletes the cookie then redirects to login page
    return response


# ---------------------------------------------------------------------------
# Routes — Dashboard
# ---------------------------------------------------------------------------

#defaulting to GET
@app.route('/dashboard')
def dashboard():
    # TODO week 3: replace with @require_auth decorator
    if not g.user:
        return redirect('/login')

    #find the documents that either belond to you or were shared to you
    docs = get_user_documents(g.user['username'])
    #take the python information/variables and match them into the html variable
    return render_template('dashboard.html', user=g.user, documents=docs)


# ---------------------------------------------------------------------------
# Routes — Documents
# ---------------------------------------------------------------------------

@app.route('/documents/upload', methods=['POST'])
def upload():
    #checking if a user is logged in, otherwise send them back to login
    if not g.user:
        return redirect('/login')

    #checking if there was a file included inside the request package from browser
    if 'file' not in request.files:
        flash('No file selected.', 'error')
        return redirect('/dashboard')

    #getting the file from the request   
    f = request.files['file']
    #if there is no name inside the file, that means there is no file inside so something
    #went wronge
    if not f.filename:
        flash('No file selected.', 'error')
        return redirect('/dashboard')

    #uses werkzeug import which sanitizes the files input, getting rid of weird or dangerous file names
    filename = secure_filename(f.filename)
    #getting the extension like txt, pdf, etc
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''

    #check if the extension is allowed or not, if its not then send them back to the dashboard
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


#just GET again
#user sends GET saying "i want the download with this link" (with doc_id inside the link)
#flask runs get_user_documents on the users name (getting variables in place)
#finds the document with the same doc id
#flask sends back the correct file
@app.route('/documents/<doc_id>/download')
def download(doc_id: str):
    #once again check if they are logged in
    if not g.user:
        return redirect('/login')

    #using the doc id from the input, find the correct document
    #doc is just the dictionary with the info about the doc
    doc = get_document(doc_id)
    if not doc:
        flash('Document not found.', 'error')
        return redirect('/dashboard')

    # TODO week 3: check access permissions properly
    #do you have access?
    if doc['owner'] != g.user['username'] and \
       g.user['username'] not in doc.get('shared_with', {}):
        flash('Access denied.', 'error')
        return redirect('/dashboard')

    # TODO week 3: decrypt file before sending
    #open up the file, using the docs "store path", go to the data/upload directory
    with open(doc['stored_path'], 'rb') as file:
        data = file.read()

    #sending the file to the browser 
    return send_file(
        #wrapping bytes into file like object
        io.BytesIO(data),
        #telling browser what to name the download file
        download_name=doc['original_name'],
        #download the file instead of trying to open it in the browser
        as_attachment=True,
    )

#POST because we arent seeing anything but want to server to do something (like sending it to someone else)
#similar to download above here, getting the document and doc id in a similar way

@app.route('/documents/<doc_id>/share', methods=['POST'])
def share(doc_id: str):
    if not g.user:
        return redirect('/login')

    #using the doc id from the input, find the correct document
    #doc is just the dictionary with the info about the doc
    doc = get_document(doc_id)
    if not doc or doc['owner'] != g.user['username']:
        flash('Access denied.', 'error')
        return redirect('/dashboard')

    #get the name that the user sent in to request form
    target = request.form.get('username', '').strip()
    #gets the role that was selected by the user, but if there was nothing then default it to viewer
    role = request.form.get('role', 'viewer')

    #if the target doesnt exist, then cancel it request and send them back to dashboard
    if not get_user_by_username(target):
        flash('User not found.', 'error')
        return redirect('/dashboard')

    #go to the dictionary for the doc and set the targets role to the selected role (also add them to the dictionary)
    doc['shared_with'][target] = role
    #save the updated dictionary
    save_document(doc)
    #notify that it was correctly and successfully done
    flash(f'Shared with {target} as {role}.', 'success')
    return redirect('/dashboard')


#just POST, client sends a request for server to do something
#getting doc once again in the same way
@app.route('/documents/<doc_id>/delete', methods=['POST'])
def delete_doc(doc_id: str):
    if not g.user:
        return redirect('/login')

    doc = get_document(doc_id)
    if not doc or doc['owner'] != g.user['username']:
        flash('Access denied.', 'error')
        return redirect('/dashboard')

    #try to get rid of the file, but if it doesnt exist the just throw an error
    try:
        os.remove(doc['stored_path'])
    except FileNotFoundError:
        pass

    #load the entire list of documents
    docs = load_documents()
    #pop it out of there
    docs.pop(doc_id, None)
    #save the updated dictionary
    save_documents(docs)

    #notify that it was successfully deleted
    flash('Document deleted.', 'success')
    return redirect('/dashboard')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)