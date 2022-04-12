from flask import Flask, render_template, url_for, redirect, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_user, LoginManager, login_required, logout_user
from os import urandom
from flask_bcrypt import Bcrypt
import os
import pathlib
import requests
from flask import Flask, session, abort, redirect, request
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests


app = Flask(__name__)


# Generate random secret key on execution.
app.config["SECRET_KEY"] = urandom(12)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.sqlite"
#Generate google scret key 
GOOGLE_CLIENT_ID = "1057527171707-kvd5kdq1r42djl2jvj6s88ul0chjobcb.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

#Redirect for google log in
flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="https://127.0.0.1:5000/callback"
)


# Stops console from being bloated with warning message.
# https://stackoverflow.com/questions/33738467/how-do-i-know-if-i-can-disable-sqlalchemy-track-modifications
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

from forms import *
from models import *

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

def googlelogin_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
def home():
    
    return render_template("home.html")

@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html")

@app.route("/googleprofile")
@googlelogin_required
def googleprofile():
    return render_template("profile.html")

@app.route("/googleform")
def googleform():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    return redirect("/googleprofile")


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if request.method == 'POST':
        if form.validate_on_submit():
            # Attempt to load user from db.
            user = User.query.filter_by(email=form.email.data).first()

            # Check if user exists and check inputted password matches db hash.
            if user and bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)

                return redirect(url_for("profile"))
            else:
                flash("Wrong email or password.")
        else:
            for fieldName, errorMessages in form.errors.items():
                for err in errorMessages:
                    flash(err)

    return render_template("login.html", form=form)

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if request.method == 'POST':
        if form.validate_on_submit():
            # Get hash of inputted password.
            hashed_password = bcrypt.generate_password_hash(form.password.data)

            # Create and populate user instance then add to db.
            user = User(email=form.email.data, password=hashed_password)
            db.session.add(user)
            db.session.commit()

            # Login the newly registered user.
            login_user(user)

            return redirect(url_for("profile"))
        else:
            for fieldName, errorMessages in form.errors.items():
                for err in errorMessages:
                    flash(err)

    return render_template("register.html", form=form)

@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    
    return redirect(url_for("home"))

if __name__ == "__main__":
     app.run(ssl_context="adhoc")