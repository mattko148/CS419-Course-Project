CS419 Secure Web Application Project
By Matthew Ko & Michael Zdunek
========================

This project is a web application that allows users to create an account, upload, share, download, and delete documents.  


How to run the program

Using linux (SSH) - Note: Linux/SSH setup was tested but did not work on iLab servers. Use Windows setup instead.

be in secure app directory

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py


------------------------

On windows:

secure app directory

Create your certificate with 

openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365

(Note: PowerShell may block script execution, so run this first:)

Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py


After running the app, please go to the terminal and go to either of the addresses where it says:

Running on https://
Where after the https:// has an ip address

There will be a warning of the website being insecure or unsafe, please advance and continue to the website

It is possible that trying to visit the site may time out, so if it does time out please try a few times and give it a few minutes



Once you get to the website you should see a login page. You should create a new account. 

As required by the directions, you must have:

Username: 3-20 characters, alphanumeric + underscore
Email: Valid email format
Password: Minimum 12 characters, complexity requirements:
At least 1 uppercase letter
At least 1 lowercase letter
At least 1 number
At least 1 special character (!@#$%^&*)
Password confirmation must match


After creating a new account, all users start as GUEST. To change your role to admin, please go to data/users.json and find your account and change your role from "guest" to "admin".
The role of admin has all the powers that other users have and more. They can download, share, and upload ALL files, including from other users regardless of if they were shared to the admin. 
Admins also have the power to change the role of other accounts. For example, an admin can change an account to any role. These roles include admin, guests, and users.
Guests can ONLY download files shared to them. They cannot upload or share files, even if they were previously a user.

To upload: Simply click the upload button and select the file you would like to upload. There is a 10 MB file size limit, and files with the same name will be replaced and updated.

To download: click the download button on a file they either you have uploaded OR has been shared to you

To share: click the share button, type the username you would like to share to, select what powers they have on the file of viewer or editor (Note: viewer and editor sharing roles are implemented but currently have no functional difference.)

To delete: click the delete button then confirm

To change your password (only when you are already logged in!): click the password button in the top right of the screen. Type in your current password, then your new password and 
confirm the new password is the same

To reach the ADMIN DASHBOARD (admin only!): look to the top right of the screen to find an "Admin" button.
To change an account role, go to the drop down for the account name and change it to whatever you would like and click save. Navigate back to your normal dashboard by clicking the dashboard button


the data/secret.key should not be deleted or shared because it is the encryption key required for all of the uploaded documents

The security and access logs can be found inside logs/security.log and logs/access.log