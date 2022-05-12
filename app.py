from flask import Flask, redirect, render_template, url_for, request
from flask_login import current_user
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, auth_required, hash_password, anonymous_user_required, login_user, roles_required
from flask_security.models import fsqla_v2 as fsqla
from flask_mail import Mail
from oauthlib.oauth2 import WebApplicationClient
from requests import get, post
from json import dumps
from flask import Flask, render_template, request, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, validators, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
from flask_bootstrap import Bootstrap
import email_validator
import csv
app = Flask(__name__)
Bootstrap(app)
# Create app

app.config.from_pyfile('config.cfg')

# Generate random secret key on execution.
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}

# Stops console from being bloated with warning message.
# https://stackoverflow.com/questions/33738467/how-do-i-know-if-i-can-disable-sqlalchemy-track-modifications
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config['SECURITY_REGISTERABLE'] = True
app.config['SECURITY_RECOVERABLE'] = True
app.config['SECURITY_CHANGEABLE'] = True
app.config["SECURITY_SEND_REGISTER_EMAIL"] = False
app.config["SECURITY_SEND_PASSWORD_RESET_NOTICE_EMAIL"] = False
app.config["SECURITY_SEND_PASSWORD_CHANGE_EMAIL"] = False

# Configuration
app.config["GOOGLE_DISCOVERY_URL"] = ("https://accounts.google.com/.well-known/openid-configuration")

mail = Mail(app)
db = SQLAlchemy(app)
client = WebApplicationClient(app.config["GOOGLE_CLIENT_ID"])

# Define models
fsqla.FsModels.set_db_info(db)

class Role(db.Model, fsqla.FsRoleMixin):
    pass

class User(db.Model, fsqla.FsUserMixin):
    pass

# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

# Function for getting Google OpenID configuration.
def get_google_provider_cfg():
    return get(app.config["GOOGLE_DISCOVERY_URL"]).json()

# Create test user and add social role for users who sign in with Google.
@app.before_first_request
def create_user():
    db.drop_all()
    db.create_all()
    if not user_datastore.find_role(role="social"):
        user_datastore.create_role(name="social", permissions=[])
    
    if not user_datastore.find_role(role="admin"):
        user_datastore.create_role(name="admin", permissions=[])
    
    if not user_datastore.find_user(email="test@me.com"):
        user_datastore.create_user(email="test@me.com", password=hash_password("password"), roles=["admin"])

    db.session.commit()

# Homepage
@app.route("/")
def home():
    return render_template("home.html")

# Sign in with Google page
@app.route("/login/google")
@anonymous_user_required
def googlelogin():
    # Find out what URL to hit for Google login
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for Google login and provide
    # scopes that let you retrieve user's profile from Google
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)

# Sign in with Google callback page
# https://realpython.com/flask-google-login/
@app.route("/login/google/callback")
@anonymous_user_required
def callback():
    # Get authorization code Google sent back to you
    code = request.args.get("code")

    # Find out what URL to hit to get tokens that allow you to ask for
    # things on behalf of a user
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    # Prepare and send a request to get tokens! Yay tokens!
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = post(
        token_url,
        headers=headers,
        data=body,
        auth=(app.config["GOOGLE_CLIENT_ID"], app.config["GOOGLE_CLIENT_SECRET"]),
    )

    # Parse the tokens!
    client.parse_request_body_response(dumps(token_response.json()))

    # Now that you have tokens (yay) let's find and hit the URL
    # from Google that gives you the user's profile information,
    # including their Google profile image and email
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = get(uri, headers=headers, data=body)

    # You want to make sure their email is verified.
    # The user authenticated with Google, authorized your
    # app, and now you've verified their email through Google!
    if not userinfo_response.json().get("email_verified"):
        return "User email not available or not verified by Google.", 400

    email = userinfo_response.json()["email"]

    user = user_datastore.find_user(email=email)

    if user and user.has_role(role="social"):
        login_user(user)

    elif user and not user.has_role(role="social"):
        return "This account is not associated with a Google Account.", 400

    else:
        # FIX: Need to fix sign in with Google users so they are not created with password and cannot be
        # logged in using standard login page.
        newuser = user_datastore.create_user(email=email, password=hash_password("password"), roles=["social"])
        db.session.commit()
        login_user(newuser)
    
    return redirect(url_for("home"))

# Profile page
@app.route("/profile")
@auth_required()
def profile():
    return render_template("profile.html")

# Delete account API
@app.route("/deleteaccount", methods=["POST"])
@auth_required()
def deleteaccount():
    user_datastore.delete_user(current_user)
    db.session.commit()
    return redirect(url_for("home"))

@app.route("/history")
@auth_required()
def history():
    return ""
#Class that contains the elements of the form
class contactForm(FlaskForm):
    name = StringField(label='Name', validators=[DataRequired()])
    email = StringField(label='Email', validators=[DataRequired(), Email(granular_message=True)])
    message = StringField(label='Message')
    submit = SubmitField(label="Submit")
@app.route("/feedback", methods=["GET", "POST"])
@auth_required()
def feedback():
    cform=contactForm()
    
    if cform.validate_on_submit():
        #Done and send
        with open('C//path//to//csv_file', 'w', encoding='UTF8') as f:
        
            writer = csv.writer(f)

            # write a row to the csv file
            writer.writerow([cform.name.data, cform.email.data,
                  cform.message.data])
        return render_template('completefeedback.html',form=cform)
    else:
        return render_template("feedback.html",form=cform)


@app.route("/viewfeedback")
@roles_required('admin')
def viewfeedback():
    return ""



@app.route("/help")
def gethelp():
    return ""

@app.route("/about")
def about():
    return ""

@app.route("/camera")
def camera():
    return ""

@app.route("/upload")
def upload():
    return ""

# SSL Adhoc so we can run app without SSL cert.
if __name__ == "__main__":
    app.run(ssl_context="adhoc")