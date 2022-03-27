from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_user, LoginManager, login_required, logout_user
from os import urandom
from flask_bcrypt import Bcrypt

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

from forms import *
from models import *

# Generate random secret key on execution.
app.config["SECRET_KEY"] = urandom(12)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.sqlite"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

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

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit:
        # Attempt to load user from db.
        user = User.query.filter_by(email=form.email.data).first()

        # Check if user exists and check inputted password matches db hash.
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)

            return redirect(url_for("profile"))

    return render_template("login.html", form=form)

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        # Get hash of inputted password.
        hashed_password = bcrypt.generate_password_hash(form.password.data)

        # Create and populate user instance then add to db.
        user = User(email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()

        # Refresh user instance to populate db id and log them in.
        db.session.refresh(user)
        login_user(user)

        return redirect(url_for("profile"))

    return render_template("register.html", form=form)

@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True)