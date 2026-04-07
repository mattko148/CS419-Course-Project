How to run the program

Using linux (SSH) DID NOT WORK ON ILABS!!!

be in secure app directory

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py


------------------------

on windows:

secure app directory

(powershell thing did not allow scripts so)

Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py

