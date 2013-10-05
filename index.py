from functools import wraps
import os
import werkzeug
import sqlite3

from flask import Flask, render_template, request, session, redirect, flash, url_for, _app_ctx_stack
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = "Development Key"

app.config["DATABASE"] = "data.db"
app.config["UPLOAD_FOLDER"] = "static/uploads"

ALLOWED_EXTENSIONS = set(['mp3'])


def sanitize_song_title(song):
    new_song = song.strip("'")
    return new_song.replace(" ", "_")


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
    if user_data[1] != user_data[2]:
        flash("Your passwords don't match!")
    if not user_data[2] or not user_data[1]:
        flash("You didn't enter a password")
    if any(c in disallowed_characters for c in user_data[0]):
        flash("The following characters are disallowed in your username (spaces,/,')")
    if not (user_data[3] and user_data[4]):
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


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function





@app.route('/upload', methods=["POST"])
def upload():
    files = request.files.getlist('file[]')
    for file in files:
        if allowed_file(file.filename):
            filename = file.filename
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], session['user'], sanitize_song_title(filename)))
            flash("File {0} uploaded!".format(file.filename))
        else:
            flash("File extension or file name is not allowed")
            return redirect(url_for('home_page'))
    return redirect(url_for("home_page"))


@app.teardown_appcontext
def close_database(Exception):
    """Closes the database again at the end of the request."""
    top = _app_ctx_stack.top
    if hasattr(top, 'sqlite_db'):
        top.sqlite_db.close()


@app.route('/', methods=["GET"])
def main():
    if "user" in session:
        flash("Logged in as user %s" % session["user"])
    return render_template("index.html")


@app.route('/info', methods=["GET"])
@login_required
def info():
    return render_template("info.html")


@app.route("/homepage")
@login_required
def home_page():
    user = session["user"]
    userData = retrieve_user_info(user)
    return render_template("home_page.html",
                           name=userData[2],
                           age=userData[3],
                           user_files=os.listdir(os.path.join(app.config['UPLOAD_FOLDER'], session['user'])))


@app.route("/logout")
def logout():
    if "user" in session:
        session.pop("user")
    return redirect("/")


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user" in session:
        return render_template("logged_in.html")
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if username and password:
            if authenticate_password(username):
                session["user"] = username
                return redirect(url_for('home_page'))
            else:
                return redirect("login")
        else:
            flash("Username or password are incorrect")
            return redirect("login")
    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        data = [request.form["username"],
                request.form["password"],
                request.form["confirm_password"],
                request.form["name"],
                request.form["age"],
                request.form["email"]]
        if register_user(data):
            flash("Your account was created and you can now log in")
            return render_template("login.html")
        else:
            return redirect(url_for("register"))
    if "user" in session:
        return redirect(url_for("home_page"))
    return render_template("register.html")


if __name__ == '__main__':
    app.run(debug=True)
