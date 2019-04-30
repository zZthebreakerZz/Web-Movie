import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
import pymysql

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ChuThoDien'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:test@localhost/chuthodien'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["UP_DIR"] = os.path.join(os.path.abspath(os.path.dirname(__file__)), "static/uploads/")

db = SQLAlchemy(app)
from . import models

mirgate = Migrate(app, db)

login = LoginManager(app)

from app.admin import admin_bp as admin_blueprint

app.register_blueprint(admin_blueprint, url_prefix='/admin')