# IMPORTS
import logging
import os
from functools import wraps
from flask_talisman import Talisman
from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user

# CONFIG
app = Flask(__name__)
app.config['SECRET_KEY'] = 'LongAndRandomSecretKey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lottery.db'
app.config['SQLALCHEMY_ECHO'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# initialise database
db = SQLAlchemy(app)

# define content security policy
csp = {
    'default-src': [
        '\'self\'',
        'https://cdnjs.cloudflare.com/ajax/libs/bulma/0.7.2/css/bulma.min.css'],
    'frame-src': [
        '\'self\'',
        'https://www.google.com/recaptcha/',
        'https://recaptcha.google.com/recaptcha/'],
    'script-src': [
        '\'self\'',
        '\'unsafe-inline\'',
        'https://www.google.com/recaptcha/',
        'https://www.gstatic.com/recaptcha/']
}

# add security headers
talisman = Talisman(app, content_security_policy=csp)
talisman.force_https = False


# Custom filter defined as a filter class type
class SecurityFilter(logging.Filter):
    # Filter takes the log record as a parameter
    def filter(self, record):
        # Returns log record if its message contains the String ‘SECURITY’
        return 'SECURITY' in record.getMessage()


# Gets the root logger
logger = logging.getLogger()
# set the level of the logger to DEBUG
logger.setLevel(logging.DEBUG)
# a file handler set to append mode
file_handler = logging.FileHandler('lottery.log', 'a')
# the level of the file handler is set to warning
file_handler.setLevel(logging.WARNING)
# adds the security filter to the file handler
file_handler.addFilter(SecurityFilter())
# Define how log records are presented in the log file
formatter = logging.Formatter('%(asctime)s : %(message)s', '%m/%d/%Y %I:%M:%S %p')
# adds the formatter to the file handler
file_handler.setFormatter(formatter)
# adds the file handler to the logger
logger.addHandler(file_handler)


def requires_roles(*roles):
    # wrap the function f with the @roles_required decorator
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # If role of user trying to access view function is not authorised
            if current_user.role not in roles:
                # log the unauthorised access attempt
                logging.warning('SECURITY - Unauthorised Access Attempt[%s, %s, %s, %s]',
                                current_user.id,
                                current_user.email,
                                current_user.role,
                                request.remote_addr)
                # render 403 - Access forbidden
                return render_template('403.html')
            return f(*args, **kwargs)
        return wrapped
    return wrapper


# HOME PAGE VIEW
@app.route('/')
def index():
    return render_template('main/index.html')


# BLUEPRINTS
# import blueprints
from users.views import users_blueprint
from admin.views import admin_blueprint
from lottery.views import lottery_blueprint

# register blueprints with app
app.register_blueprint(users_blueprint)
app.register_blueprint(admin_blueprint)
app.register_blueprint(lottery_blueprint)

# create a login manager
login_manager = LoginManager()
# Anonymous users redirected to login page (rendered by login() view function)
login_manager.login_view = 'users.login'
login_manager.init_app(app)

from models import User


# Creates a user loader function
@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


# Handles an error with the code 400
@app.errorhandler(400)
def bad_request(error):
    return render_template('400.html'), 400


# Handles an error with the code 403
@app.errorhandler(403)
def forbidden(error):
    return render_template('403.html'), 403


# Handles an error with the code 404
@app.errorhandler(404)
def notfound(error):
    return render_template('404.html'), 404


# Handles an error with the code 500
@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500


# Handles an error with the code 503
@app.errorhandler(503)
def service_unavailable(error):
    return render_template('503.html'), 503


# Set public and private keys for reCAPTCHA
app.config['RECAPTCHA_PUBLIC_KEY'] = os.getenv('RECAPTCHA_PUBLIC_KEY')
app.config['RECAPTCHA_PRIVATE_KEY'] = os.getenv('RECAPTCHA_PRIVATE_KEY')


if __name__ == "__main__":
    app.run()
