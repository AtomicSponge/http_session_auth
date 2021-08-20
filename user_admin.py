##########################################################
#
#  Python Web Auth Framework - User DB Admin
#
##########################################################
#
#  Filename:  user_admin.py
#  Version:  041521
#  By:  Matthew Evans
#       https://www.wtfsystems.net/
#
#  See LICENSE.md for copyright information.
#
#  Administration script for user database.
#  Has options for creating a new database file,
#  listing users, adding a user, or deleting a user.
#
##########################################################

import random, string, argparse, sqlite3, pyDes
from http_auth_framework import http_auth as config

config.DES_KEY = b'\0\0\0\0\0\0\0\0'
config.PATH_TO_USER_DB = 'user.db'

##########################################################
#  Function to add a new user
##########################################################
def new_user(USERNAME, PASSWORD):
    #  Generate the salt
    letter_string = ''.join(random.choice(string.ascii_letters) for x in range(128))
    number_string = ''.join(random.choice(string.digits) for x in range(128))
    SALT = ''.join(map(''.join, zip(letter_string, number_string)))

    k = pyDes.des(b"DESCRYPT",
              pyDes.CBC,
              config.DES_KEY,
              pad=config.DES_PAD,
              padmode=config.DES_PADMODE)
    PASSWORD = k.encrypt(PASSWORD + SALT)
    try:
        dbconn = sqlite3.connect(config.PATH_TO_USER_DB)
        dbquery = dbconn.cursor()
        dbquery.execute("INSERT INTO users VALUES(?,?,?)", (USERNAME,SALT,PASSWORD))
        dbconn.commit()
        dbconn.close()
        print("Created new user", USERNAME)
    except sqlite3.Error as error:
        print("Failed to create new user ", error)

##########################################################
#  Function to delete a user
##########################################################
def delete_user(USERNAME):
    try:
        dbconn = sqlite3.connect(config.PATH_TO_USER_DB)
        dbquery = dbconn.cursor()
        dbquery.execute("DELETE FROM users WHERE name=?", (USERNAME,))
        dbconn.commit()
        dbconn.close()
        print("Deleted user", USERNAME)
    except sqlite3.Error as error:
        print("Failed to delete user ", error)

##########################################################
#  Function to list users in the database
##########################################################
def list_users():
    print("Listing users in database...")

    try:
        #  Get all users
        dbconn = sqlite3.connect(config.PATH_TO_USER_DB)
        dbquery = dbconn.cursor()
        dbquery.execute("SELECT name FROM users")
        dbres = dbquery.fetchall()
        dbconn.close()

        #  No users in database
        if dbres == None:
            print("No users found!")
            return

        #  Print the list
        for dbusers in dbres:
            for dbuser in dbusers:
                print(" - ", dbuser)
    except sqlite3.Error as error:
        print("Failed listing users ", error)

##########################################################
#  Function to create the database
##########################################################
def create_database():
    print("Verifying file does not exist...")
    try:
        f = open(config.PATH_TO_USER_DB)
        f.close()
        print("File exists")
        return
    except IOError:
        pass
    finally:
        pass

    print("Creating test user database...")

    try:
        dbconn = sqlite3.connect(config.PATH_TO_USER_DB)
        dbquery = dbconn.cursor()
        dbquery.execute("CREATE TABLE users (name TEXT NOT NULL UNIQUE, salt TEXT NOT NULL, pass BLOB NOT NULL, PRIMARY KEY(name))")
        dbconn.commit()
        dbconn.close()
    except sqlite3.Error as error:
        print("Failed creating database ", error)

##########################################################
#  Main program
##########################################################
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="User admin.")
    parser.add_argument(
        "--new_db", dest="new_db", default=False,
        action="store_true", help="Create new user database file"
    )
    parser.add_argument(
        "--list", dest="list_users", default=False,
        action="store_true", help="List users in the database"
    )
    parser.add_argument(
        "-n", "--new", dest="new_user", default=False,
        action="store_true", help="Add a new user to the database"
    )
    parser.add_argument(
        "-d", "--delete", dest="delete_user", default=False,
        action="store_true", help="Delete a user from the database"
    )
    parser.add_argument("username", nargs='?', type=str, default=None, help="Username")
    parser.add_argument("password", nargs='?', type=str, default=None, help="Password")
    args = parser.parse_args()

    #  Create a new database
    if args.new_db:
        create_database()
    #  List users
    elif args.list_users:
        list_users()
    #  Create a new user
    elif args.new_user:
        if args.username == None:
            username = input("Enter a username: ")
        else:
            username = args.username
        if args.password == None:
            password = input("Enter a Password: ")
        else:
            password = args.password
        new_user(username, password)
    #  Delete a user
    elif args.delete_user:
        if args.username == None:
            username = input("Enter a username: ")
        else:
            username = args.username
        delete_user(username)
    else:
        print("Please choose an option or --help for a list of commands.")

    print("Done!")
    print()
