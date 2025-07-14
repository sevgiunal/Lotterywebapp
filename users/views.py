# IMPORTS
import logging
from datetime import datetime
import bcrypt
import pyotp
from flask import Blueprint, render_template, flash, redirect, url_for, session, request
from flask_login import login_user, logout_user, login_required, current_user
from markupsafe import Markup
from app import db, requires_roles
from models import User
from users.forms import RegisterForm, LoginForm

# CONFIG
users_blueprint = Blueprint('users', __name__, template_folder='templates')


# VIEWS
# view registration
@users_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    # create signup form object
    form = RegisterForm()

    # if request method is POST or form is valid
    if form.validate_on_submit():

        # query user by email
        user = User.query.filter_by(email=form.email.data).first()

        # if email already exists redirect user back to signup page with error message so user can try again
        if user:
            flash('Email address already exists')
            return render_template('users/register.html', form=form)

        # create a new user with the form data
        new_user = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        phone=form.phone.data,
                        password=form.password.data,
                        role='user')

        logging.warning('SECURITY - Register[%s, %s]',
                        form.email.data,
                        request.remote_addr)

        # add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        # sends user to login page
        return redirect(url_for('users.login'))
    # if request method is GET or form not valid re-render signup page
    return render_template('users/register.html', form=form)


# view user login
@users_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    # Check if authentication attempts exists
    if not session.get('authentication_attempts'):
        # If it does not exist, set the variable to 0
        session['authentication_attempts'] = 0

    # create login form object
    form = LoginForm()

    # if request method is POST or form is valid
    if form.validate_on_submit():
        # query user by email
        user = User.query.filter_by(email=form.email.data).first()
        # if user does not exist or password is incorrect or if pin is incorrect
        if not user or not bcrypt.checkpw(form.password.data.encode('utf-8'), user.password) or not pyotp.TOTP(user.pinkey).verify(form.pin.data):
            # Increment authentication attempts by 1
            session['authentication_attempts'] += 1
            # if authentication attempts is bigger than or equal to 3
            if session.get('authentication_attempts') >= 3:

                # display a reset link and flash an error
                flash(Markup('Number of incorrect login attempts exceeded.Please click <a href="/reset"> here </a> to reset.'))
                return render_template('users/login.html')
            # log all the invalid login attempts
            logging.warning('SECURITY - Invalid Login Attempt[%s, %s]',
                            form.email.data,
                            request.remote_addr)
            flash('Please check your login details and try again, {} login attempts remaining'.format(3 - session.get('authentication_attempts')))
            return render_template('users/login.html', form=form)

        # reset the amount of authentication attempts
        reset()
        # log the user in after authenticating
        login_user(user)
        # set the last login of the user as the current login in the database
        user.last_login = user.current_login
        # set the current login as the current date
        user.current_login = datetime.now()
        # log the login of the user
        logging.warning('SECURITY - Log in[%s, %s, %s]',
                        current_user.id,
                        current_user.email,
                        request.remote_addr)
        # add the data into the database
        db.session.add(user)
        db.session.commit()

        # if the role of the logged-in user is user
        if current_user.role == 'user':
            # redirect to the profile page
            return redirect(url_for('users.profile'))
        # else if it's admin
        elif current_user.role == 'admin':
            # redirect to the admin page
            return redirect(url_for('admin.admin'))
    return render_template('users/login.html', form=form)


# view user profile
@users_blueprint.route('/profile')
# login is required to access this function
@login_required
# this function requires the role user
@requires_roles('user')
def profile():
    return render_template('users/profile.html', name=current_user.firstname)


# view user account
@users_blueprint.route('/account')
# login is required to access this function
@login_required
# this function requires the role admin or user
@requires_roles('admin', 'user')
def account():
    return render_template('users/account.html',
                           acc_no=current_user.id,
                           email=current_user.email,
                           firstname=current_user.firstname,
                           lastname=current_user.lastname,
                           phone=current_user.phone)


# this function resets the authentication attempts
@users_blueprint.route('/reset')
def reset():
    session['authentication_attempts'] = 0
    return redirect(url_for('users.login'))


# this function logs the user out
@users_blueprint.route('/logout')
# login is required to access this function
@login_required
# this function requires the role admin or user
@requires_roles('user', 'admin')
def logout():

    logging.warning('SECURITY - Log out[%s, %s, %s]',
                    current_user.id,
                    current_user.email,
                    request.remote_addr)
    logout_user()
    return redirect(url_for('index'))


