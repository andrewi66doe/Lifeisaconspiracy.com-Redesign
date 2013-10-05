import sqlite3
import os
import werkzeug

from flask import request, flash,  _app_ctx_stack
from werkzeug.security import check_password_hash, generate_password_hash

from index import app


def retrieve_user_info(username):
    return query_db("SELECT * FROM user_data WHERE username=?", [username], one=True)


def get_db():
    """Opens a new database connection if there is none yet for the current application context."""
    top = _app_ctx_stack.top
    if not hasattr(top, 'sqlite_db'):
        top.sqlite_db = sqlite3.connect(app.config["DATABASE"])
        top.sqlite_db.row_factory = sqlite3.Row
    return top.sqlite_db


def query_db(query, args=(), one=False):
    """Queries the database and returns a list of dictionaries."""
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv


def username_exists(user_name):
    user_names = query_db("SELECT username FROM user_data WHERE username=?", [user_name])
    if user_names:
        return True
    else:
        return False


def authenticate_password(username):
    if not username_exists(username):
        return False
    hashed_password = query_db("SELECT password FROM user_data WHERE username=?", [username], one=True)[0]
    if check_password_hash(hashed_password, request.form["password"]):
        return True
    else:
        return False


def register_user(user_data):
    """Registers a user in the database, returns False and flashes an error if an error occurs"""
    disallowed_characters = [" ", "/", "'"]
    if username_exists(user_data[0]):
        flash("That username is already taken!")
    elif user_data[1] != user_data[2]:
        flash("Your passwords don't match!")
    elif not user_data[2] or not user_data[1]:
        flash("You didn't enter a password")
    elif any(c in disallowed_characters for c in user_data[0]):
        flash("The following characters are disallowed in your username (spaces,/,')")
    elif not (user_data[3] and user_data[4]):
        flash("It looks like you didn't enter your name or age")
    else:
        db = get_db()
        db.execute("INSERT INTO user_data\
                    (password,username,name,age,bio)\
                     VALUES (?,?,?,?,?)", [generate_password_hash(user_data[1]),
                                           werkzeug.secure_filename(user_data[0]),
                                           user_data[3],
                                           user_data[4],
                                           user_data[5]])
        db.commit()
        os.mkdir(os.path.join('static/uploads', werkzeug.secure_filename(user_data[0])))
        return True
    return False


def init_database():
    conn = sqlite3.connect(app.config["DATABASE"])
    c = conn.cursor()
    try:
        c.execute("CREATE TABLE user_data (password VARCHAR(255),\
                                           username VARCHAR(255),\
                                           name VARCHAR(255),\
                                           age INT,\
                                           bio TEXT)")
        conn.commit()
        conn.close()
    except sqlite3.OperationalError:
        print "The database has already been initialized exiting....."