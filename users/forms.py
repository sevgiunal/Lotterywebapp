# IMPORTS
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email, ValidationError, Length, EqualTo
import re


# Checks for excluded characters
def character_check(form, field):
    excluded_chars = "* ? ! ' ^ + % & / ( ) = } ] [ { $ # @ < >"
    for char in field.data:
        if char in excluded_chars:
            # Raise validation error if excluded chars is found
            raise ValidationError(f"Character {char} is not allowed.")


# Checks for certain data requirements using regex
def validate_data(form, data_field):
    p = re.compile(r'(?=.*\d)(?=.*[A-Z])(?=.*[a-z])(?=.*\W)')
    if not p.match(data_field.data):
        # Raise validation error if data requirements are not met
        raise ValidationError("Please include one digit, one lowercase, one uppercase, and one special character")


# Checks if entered phone number is in a valid format
def phone_validate(form, data):
    p = re.compile(r'(\d\d\d\d-\d\d\d-\d\d\d\d)')
    if not p.match(data.data):
        # Raise validation error if phone is not in a valid format
        raise ValidationError("Must be digits of the form: XXXX-XXX-XXXX (including the dashes)")


# Defines the fields for registering a user with checks
class RegisterForm(FlaskForm):
    email = StringField(validators=[DataRequired(), Email()])
    firstname = StringField(validators=[DataRequired(), character_check])
    lastname = StringField(validators=[DataRequired(), character_check])
    phone = StringField(validators=[DataRequired(), phone_validate])
    password = PasswordField(validators=[DataRequired(), Length(min=6, max=12), validate_data])
    confirm_password = PasswordField(
        validators=[DataRequired(), EqualTo('password', message="Passwords must be equal")])
    submit = SubmitField(validators=[DataRequired()])


# Defines the fields for logging in a user with checks
class LoginForm(FlaskForm):
    email = StringField(validators=[DataRequired(), Email()])
    password = PasswordField(validators=[DataRequired()])
    submit = SubmitField()
    recaptcha = RecaptchaField()
    pin = StringField(validators=[DataRequired()])