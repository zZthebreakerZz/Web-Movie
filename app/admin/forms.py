from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, FileField, TextAreaField, SelectMultipleField
from wtforms.validators import DataRequired
from wtforms.fields.html5 import DateField, TimeField
from app.models import Tag

class LoginForm(FlaskForm):
    username = StringField(label='Admin', validators=[DataRequired()])
    password = PasswordField(label='Password', validators=[DataRequired()])
    submit = SubmitField("Let's go")

class MovieForm(FlaskForm):
    name = StringField(label="Title", validators=[DataRequired("Please enter a name")])
    poster = StringField(label="Poster", validators=[DataRequired("Please enter a poster")])
    source = StringField(label="Movie Link", validators=[DataRequired("Please enter a url")])
    desc = TextAreaField(label="Description", validators=[DataRequired("Please enter a description")])
    tag = SelectMultipleField(label="Tag", validators=[DataRequired("Please select at least one tag")], coerce=int)
    country = StringField(label="Country", validators=[DataRequired("Please enter a country")])
    release = DateField(label="Release Date", validators=[DataRequired("Please enter a time release")])
    length = TimeField(label="Length", validators=[DataRequired("Please enter length movie")])
    upload = SubmitField("Upload")

class RoleForm(FlaskForm):
    name = StringField(label="Role", validators=[DataRequired("Please enter a role")])
    auth = SelectMultipleField(label="Auths", validators=[DataRequired("Please select at least one auth")], coerce=int)
    submit = SubmitField("Add Role")

class TagForm(FlaskForm):
    name = StringField(label="Tag", validators=[DataRequired("Please enter a tag")])
    submit = SubmitField("Add Tag")

class AuthForm(FlaskForm):
    name = StringField(label="Auth", validators=[DataRequired("Please enter a auth")])
    submit = SubmitField("Add Auth")