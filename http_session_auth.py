##########################################################
#
#  Python Web Auth Framework
#
##########################################################
#
#  Filename:  http_auth_framework.py
#  Version:  041521
#  By:  Matthew Evans
#       https://www.wtfsystems.net/
#
#  See LICENSE.md for copyright information.
#  See README.md for usage information.
#
##########################################################

import random, string, datetime, sqlite3, pyDes
from flask import Flask, render_template, make_response, session

class http_auth:
    ## Set DES key
    DES_KEY = b'\0\0\0\0\0\0\0\0'
    ## Set DES padding
    DES_PAD = None
    ## Set DES pad mode
    DES_PADMODE = pyDes.PAD_PKCS5
    ## Set password minimum length
    PASS_MIN_LENGTH = 8
    ## Set password maximum length
    PASS_MAX_LENGTH = 32
    ## Toggle password case checking
    CHECK_CASE = True
    ## Toggle password symbol checking
    CHECK_SYMBOL = True
    ## Toggle password number checking
    CHECK_NUMBER = True
    ## Symbol list to check password against
    SYMBOL_LIST = '[@_!#$%^&*()<>?|}{~:]'
    ## Path to the user database file
    PATH_TO_USER_DB = 'user.db'

    ##########################################################
    ##  Constructor
    ##########################################################
    def __init__(self):
        self.__AUTH_KEY = 'xxx'

    ##########################################################
    ##  Validate user credentials
    #  @param usernm Username
    #  @param passwd Password
    #  @ return True if valid credentials, false if not
    ##########################################################
    def validate_credentials(self, usernm, passwd):
        #  Get the user's salt
        try:
            dbconn = sqlite3.connect(self.PATH_TO_USER_DB)
            dbquery = dbconn.cursor()
            dbquery.execute('SELECT salt FROM users WHERE name=?', (usernm,))
            dbres = dbquery.fetchone()
            dbconn.close()
        except: return False

        try:
            for dbsalt in dbres: SALT = dbsalt
        except: return False

        #  Hash the passed password and retrieved salt
        k = pyDes.des(b'DESCRYPT',
                      pyDes.CBC,
                      self.DES_KEY,
                      pad=self.DES_PAD,
                      padmode=self.DES_PADMODE)
        passwd = k.encrypt(passwd + SALT)

        #  Find the stored password in the user db
        try:
            dbconn = sqlite3.connect(self.PATH_TO_USER_DB)
            dbquery = dbconn.cursor()
            dbquery.execute('SELECT pass FROM users WHERE name=?', (usernm,))
            dbres = dbquery.fetchone()
            dbconn.close()
        except: return False

        #  User does not exist
        if dbres == None: return False

        #  Check the hashed password against the results
        for dbpw in dbres:
            if dbpw == passwd: return True  #  Password matched
        return False  #  Password did not match

    ##########################################################
    ##  Create a new session
    #  @param usernm Username
    #  @param passwd Password
    #  @return True on success, false on fail
    ##########################################################
    def create_session(self, usernm, passwd):
        if self.validate_credentials(usernm, passwd) == True:
            #  Generate an auth key
            letter_string = ''.join(random.choice(string.ascii_letters) for x in range(32))
            number_string = ''.join(random.choice(string.digits) for x in range(32))
            combined_string = ''.join(map(''.join, zip(letter_string, number_string)))
            self.__AUTH_KEY = str(datetime.datetime.now()) + combined_string
            #  Set session data
            global session
            session['sessionID'] = self.__AUTH_KEY
            session['userID'] = usernm
            return True
        return False

    ##########################################################
    ##  Delete the current session
    ##########################################################
    def delete_session(self):
        self.__AUTH_KEY = 'xxx'
        global session
        session.pop('sessionID', None)
        session.pop('userID', None)

    ##########################################################
    ##  Verify session is valid
    #  @return True if valid, false if not
    ##########################################################
    def check_session(self):
        global session
        if 'sessionID' in session:
            if len(session['sessionID']) > 64:  #  Check for valid length
                if session['sessionID'] == self.__AUTH_KEY: return True
        return False

    ##########################################################
    ##  Display a page if the session is valid
    #  @param redirect Template to redirect to
    #  @return Returns either the requested template, or the login template
    ##########################################################
    def validate_auth_redirect(self, redirect):
        if self.check_session(): return make_response(render_template(redirect))
        return make_response(render_template('login.html'))

    ##########################################################
    ##  Validate password complexity
    #  @param passwd Password to validate
    #  @return True if valid, false if not
    ##########################################################
    def validate_password(self, passwd):
        #  Check minimum length
        if len(passwd) < self.PASS_MIN_LENGTH: return False
        #  Check maximum length
        if len(passwd) > self.PASS_MAX_LENGTH: return False
        #  Check for both lower and uppercase
        if self.CHECK_CASE == True:
            LOWER_CHECK = False
            UPPER_CHECK = False
            for letter in passwd:
                if letter.islower():
                    LOWER_CHECK = True
                    break
            for letter in passwd:
                if letter.isupper():
                    UPPER_CHECK = True
                    break
            if (LOWER_CHECK == False) or (UPPER_CHECK == False): return False
        #  Check for a symbol
        if self.CHECK_SYMBOL == True:
            SYMBOL_FOUND = False
            for letter in passwd:
                for symbol in self.SYMBOL_LIST:
                    if letter == symbol:
                        SYMBOL_FOUND = True
                        break
            if SYMBOL_FOUND == False: return False
        #  Check for a number
        if self.CHECK_NUMBER == True:
            NUMBER_FOUND = False
            for letter in passwd:
                if letter.isnumeric():
                    NUMBER_FOUND = True
                    break
            if NUMBER_FOUND == False: return False
        return True

    ##########################################################
    ##  Change user's password
    #  @param usernm Username
    #  @param oldpasswd Old password
    #  @param newpasswd New password
    #  @return True if changed, false if not
    ##########################################################
    def change_password(self, usernm, oldpasswd, newpasswd):
        if self.validate_credentials(usernm, oldpasswd) == True:
            #  Get the user's salt
            try:
                dbconn = sqlite3.connect(self.PATH_TO_USER_DB)
                dbquery = dbconn.cursor()
                dbquery.execute('SELECT salt FROM users WHERE name=?', (usernm,))
                dbres = dbquery.fetchone()
                dbconn.close()
            except: return False

            try:
                for dbsalt in dbres: SALT = dbsalt
            except: return False

            #  Encrypt new passwd
            k = pyDes.des(b'DESCRYPT',
                          pyDes.CBC,
                          self.DES_KEY,
                          pad=self.DES_PAD,
                          padmode=self.DES_PADMODE)
            new_passwd = k.encrypt(newpasswd + SALT)

            #  Write new passwd
            try:
                dbconn = sqlite3.connect(self.PATH_TO_USER_DB)
                dbquery = dbconn.cursor()
                dbquery.execute('UPDATE users SET pass=? WHERE name=?', (new_passwd, usernm))
                dbconn.commit()
                dbconn.close()
            except: return False
            return True
        return False
