"""
Universal Exports
Flask routes

Determines routes for Universal Exports website

This program utilizes the methods within db_functions and password_db
to hash passwords, compare user input to database information,
and add users to database file (userLogin.db)

"""

from flask import Flask, render_template, request, url_for, flash, redirect, session
from db_functions import check_passwords
from password_db import validate_password, add_user_from_webpage, create_user_password
import os


app = Flask(__name__, static_folder='static')
app.config["SECRET_KEY"] = os.urandom(20) #create random secret key


@app.route("/")
def home():
    """Home page """
    if 'pass_choice' in session:
        session['pass_choice'] = 'ask'
    if "login_attempts" not in session:
        session["login_attempts"] = 0
    if 'authenticate' not in session:
        session['authenticate'] = False
    if session["login_attempts"] < 2:

        return render_template("index.html")
    else:
        return redirect(url_for("failed_login"))

@app.route("/login", methods=["POST", "GET"])
def login():
    if 'login_attempts' not in session:
        session['login_attempts'] = 0
    if session["login_attempts"] < 2:
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')

            try:
                user, clearance = check_passwords(username, password)
                session["authenticate"] = True
                session["username"] = username
                session["clearance"] = clearance
                return redirect(url_for("login_success"))
            except TypeError:
                session['authenticate'] = False
                session["login_attempts"] = session["login_attempts"] + 1
                flash("Invalid Credentials")
                render_template("login.html")

        return render_template("login.html")
    else:
        return redirect(url_for("failed_login"))

@app.route("/login_success")
def login_success():
    if "login_attempts" not in session:
        session['login_attempts'] = 0
        return redirect(url_for('login'))
    if session["login_attempts"] < 2 and session["authenticate"] == True:
        return render_template("login_success.html", content=session["username"], clearance=session["clearance"])
    elif session['authenticate'] == False and session['login_attempts'] < 2:
        return redirect(url_for('login'))
    else:
        return redirect(url_for("failed_login"))


@app.route("/register", methods=["POST", "GET"])
def register():

    if 'pass_choice' not in session:
        session['pass_choice'] = 'ask'
    if session['pass_choice'] == 'ask' and request.method == 'POST':
        if request.form.get('autoPass'):
            session['pass_choice'] = 'auto'
        elif request.form.get('myOwnPass'):
            session['pass_choice'] = 'myOwn'
        return render_template("register_user.html", password_option=session['pass_choice'])

    elif request.method == 'POST' and session['pass_choice'] == 'myOwn':
        username = request.form.get('username')
        password = request.form.get('password')
        if validate_password(password) == True:
            session['authenticate'] = True
            if add_user_from_webpage(username, password):
                session["username"] = username
                session["clearance"] = "bronze"
                return redirect(url_for('login_success', user=username))
        else:
            flash('Password must be between 8-25 characters long, contain a capital '
                  'and lowercase, number, and a special character')
            return render_template("register_user.html", password_option=session['pass_choice'])

    elif request.method == 'POST' and session['pass_choice'] == 'auto':
        username = request.form.get('username')
        password = create_user_password()
        if add_user_from_webpage(username, password):
            session['username'] = username
            session["clearance"] = "bronze"
            session['authenticate'] = True
            flash('Account Password: ' + password)
            return redirect(url_for('login_success', user=username))
    return render_template("register_user.html", password_option=session['pass_choice'])


@app.route("/failed_login")
def failed_login():
    if "login_attempts" not in session:
        session['login_attempts'] = 0
        return redirect(url_for('login'))
    if session['login_attempts'] < 2:
        return redirect(url_for('login'))
    else:
        return render_template("failed_login.html")


@app.route("/time_reporting")
def time_reporting():
    if "login_attempts" not in session:
        session['login_attempts'] = 0
        return redirect(url_for('login'))
    if session['authenticate'] == True and session["login_attempts"] < 2:
        return render_template("time_reporting.html")
    elif session['authenticate'] == False and session['login_attempts'] < 2:
        return redirect(url_for('login'))
    else:
        return redirect(url_for("failed_login"))


@app.route("/IT_help")
def IT_help():
    if "login_attempts" not in session:
        session['login_attempts'] = 0
    if 'authenticate' not in session:
        session['authenticate'] = False
    if session['authenticate'] == True and session["login_attempts"] < 2:
        return render_template("IT_help.html")
    elif session['authenticate'] == False and session['login_attempts'] < 2:
        return redirect(url_for('login'))
    else:
        return redirect(url_for("failed_login"))
@app.route("/accounting")
def accounting():
    if "login_attempts" not in session:
        session['login_attempts'] = 0
    if 'authenticate' not in session:
        session['authenticate'] = False
    if session['authenticate'] == True and session["login_attempts"] < 2:
        if session['clearance'] == 'gold' or session['clearance'] == 'silver':
            return render_template("accounting.html")
        else:
            return redirect(url_for('login_success'))
    elif session['authenticate'] == False and session['login_attempts'] < 2:
        return redirect(url_for('login'))
    else:
        return redirect(url_for("failed_login"))

@app.route("/engineering_documents")
def engineering_documents():
    if "login_attempts" not in session:
        session['login_attempts'] = 0
    if 'authenticate' not in session:
        session['authenticate'] = False
    if session['authenticate'] == True and session["login_attempts"] < 2:
        if session['clearance'] == 'gold' or session['clearance'] == 'silver':
            return render_template("engineering_documents.html")
        else:
            return redirect(url_for('login_success'))
    elif session['authenticate'] == False and session['login_attempts'] < 2:
        return redirect(url_for('login'))
    else:
        return redirect(url_for("failed_login"))
@app.route("/universal_exports")
def universal_exports():
    if "login_attempts" not in session:
        session['login_attempts'] = 0
    if 'authenticate' not in session:
        session['authenticate'] = False
    if session['authenticate'] == True and session["login_attempts"] < 2:
        if session['clearance'] == 'gold':
            return render_template("universal_exports.html")
        else:
            return redirect(url_for('login_success'))
    elif session['authenticate'] == False and session['login_attempts'] < 2:
        return redirect(url_for('login'))
    else:
        return redirect(url_for("failed_login"))


@app.route("/logout")
def logout_user():
    if "login_attempts" not in session:
        session['login_attempts'] = 0
    if 'authenticate' not in session:
        session['authenticate'] = False
    if session["authenticate"] == True:
        session["login_attempts"] = 0
        session["authenticate"] = False
        session['pass_choice'] = 'ask'
        app.config["SECRET_KEY"] = os.urandom(20)
        return redirect(url_for("home"))
    else:
        return redirect(url_for("failed_login"))


