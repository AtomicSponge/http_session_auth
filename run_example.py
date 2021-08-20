##########################################################
#
#  Python Web Auth Framework Example
#
##########################################################
#
#  Filename:  run_example.py
#  By:  Matthew Evans
#       https://www.wtfsystems.net/
#
#  See LICENSE.md for copyright information.
#  See README.md for usage information.
#
##########################################################

from flask import Flask, render_template, request, \
    make_response, url_for, flash, redirect, session

import http_auth_framework

#################################
#####  Flask configuration  #####
#  Set the secret key for Flask:
FLASK_SECRET_KEY = b'_5#y2L"F4Q8z\n\xec]/'
#  Set host IP for Flask:
FLASK_HOST_IP = '0.0.0.0'
#  Enable/disable Flask debugging:
FLASK_DEBUG_MODE = True
#  Set up Flask
app = Flask(__name__)
app.config.update(
    SECRET_KEY=FLASK_SECRET_KEY,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
)
#################################

#################################
###  Http Auth configuration  ###
auth = http_auth_framework.http_auth()
auth.DES_KEY = b'\0\0\0\0\0\0\0\0'
#################################

##########################################################
#  Log in request
##########################################################
@app.route('/dologin', methods = ['POST', 'GET'])
def dologin():
    if request.method == 'POST':
        login_result = auth.create_session(request.form['username'],
                                           request.form['passwd'])
        #  If invalid login
        if login_result == False:
            flash("Invalid login attempt!")
    return redirect(url_for('index'))

##########################################################
#  Log out request
##########################################################
@app.route('/dologout', methods = ['POST', 'GET'])
def dologout():
    auth.delete_session()
    return make_response(render_template('login.html'))

##########################################################
#  Change password request
##########################################################
@app.route('/dochangepw', methods = ['POST', 'GET'])
def dochangepw():
    #  Make sure the session is valid
    if auth.check_session() == False: return make_response(render_template('login.html'))
    if request.method == 'POST':
        old_password = request.form['oldpw']
        new_password_a = request.form['newpw1']
        new_password_b = request.form['newpw2']

        #  Validate the old password
        login_result = auth.validate_credentials(session['userID'], old_password)
        if login_result == False:
            flash("Old password incorrect!")
            return redirect(url_for('settings'))

        #  Make sure new passwords match
        if new_password_a != new_password_b:
            flash("Passwords do not match!")
            return redirect(url_for('settings'))

        #  Verify password complexity
        if auth.validate_password(new_password_a) == False:
            flash("Password not complex enough!")
            return redirect(url_for('settings'))

        res = auth.change_password(session['userID'], old_password, new_password_a)
        if res == False: flash("Error changing password!")
        else: flash("Password changed!")
        return redirect(url_for('settings'))
    return auth.validate_auth_redirect('settings.html')

##########################################################
#  Settings page
##########################################################
@app.route('/settings', methods = ['GET'])
def settings():
    return auth.validate_auth_redirect('settings.html')

##########################################################
#  Main page
##########################################################
@app.route('/', methods = ['GET'])
def index():
    return auth.validate_auth_redirect('main.html')

##########################################################
#  404 Handler
##########################################################
@app.errorhandler(404)
def not_found_error(error):
    return auth.validate_auth_redirect('main.html')

##########################################################
#  App start
##########################################################
if __name__ == '__main__':
    app.run(debug = FLASK_DEBUG_MODE, host = FLASK_HOST_IP)
