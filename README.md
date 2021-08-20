##  Python/Flask Web Authentication Framework

Python web authentication using Flask and SQLite.  Provides a login framework to base small web gui projects around.

Authenticates a user against a SQLite database file.  Passwords are hashed and stored using DES encryption and a salt.

-----

#### Requirements
Requires the following packages to be installed:
- [flask](https://flask.palletsprojects.com)
- [pyDes](http://whitemans.ca/des.html)

__Note:__ Make sure to configure https to avoid sending credentials in plain text!

-----

#### Usage

First import the file:
```
import http_auth_framework
```

Then create an instance of the class:
```
auth = http_auth_framework.http_auth()
```

Next set any parameter values:
```
auth.DES_KEY = b'\0\0\0\0\0\0\0\0'
```

To log a user in, use the __create_session__ member:
```
login_result = auth.create_session(request.form['username'], request.form['passwd'])
```

Use __delete_session__ to clear the session:
```
@app.route('/dologout', methods = ['POST', 'GET'])
def dologout():
    auth.delete_session()
    return make_response(render_template('login.html'))
```

Now for any page routes, call the template with __validate_auth_redirect__.
If the user is not logged in, they will be redirected to the login page:
```
@app.route('/', methods = ['GET'])
def index():
    return auth.validate_auth_redirect('main.html')
```

You can also use the member __check_session__:
```
if auth.check_session() == False:
    return make_response(render_template('login.html'))
```

The __http_auth__ class also has members for validating and changing a user's password.

-----

#### Example

The file [run_example.py](https://github.com/wtfsystems/snippets/blob/master/http_auth_framework/run_example.py) provides a working Flask application as an example.

-----

#### Configuration

List of configuration class variables and their default values.

- Set the key used for DES encryption
```
DES_KEY = b'\0\0\0\0\0\0\0\0'
```

- Set the DES padding
```
DES_PAD = None
```

- Set the DES pad mode.
```
DES_PADMODE = pyDes.PAD_PKCS5
```

- Set the valid password minimum length
```
PASS_MIN_LENGTH = 8
```

- Set the valid password maximum length
```
PASS_MAX_LENGTH = 32
```

- Toggle password case checking
```
CHECK_CASE = True
```

- Toggle password symbol checking
```
CHECK_SYMBOL = True
```

- Toggle password number checking
```
CHECK_NUMBER = True
```

- Symbol list to check password against
```
SYMBOL_LIST = '[@_!#$%^&*()<>?|}{~:]'
```

- Path to the user database file
```
PATH_TO_USER_DB = 'user.db'
```

-----

#### User Database Admin
The script [user_admin.py](https://github.com/wtfsystems/snippets/blob/master/http_auth_framework/user_admin.py) creates a useable database file for the framework.  Also has commands to add, delete and list users.

__Commands:__
- --new_db - Generates a new database file if one does not already exist.
- --list - List users in the database.
- -n *username* *password* - Adds a new user
- -d *username* - Deletes a user
