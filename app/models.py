from datetime import datetime
from app import db
from werkzeug.security import check_password_hash, generate_password_hash

class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, index=True)
    phone = db.Column(db.String(15), unique=True)
    created = db.Column(db.DateTime, index=True, default=datetime.now)
    comments = db.relationship("Comment", backref="user", lazy="dynamic")

    def __repr__(self):
        return '<User {}>'.format(self.name)

class Comment(db.Model):
    __tablename__ = "comment"
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    movie_id = db.Column(db.Integer, db.ForeignKey('movie.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created = db.Column(db.DateTime, index=True, default=datetime.utcnow)

    def __repr__(self):
        return "<Comment {}>".format(self.id)

tags = db.Table('tags',
                db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'), primary_key=True),
                db.Column('movie_id', db.Integer, db.ForeignKey('movie.id'), primary_key=True),
                )

class Tag(db.Model):
    __tablename__ = "tag"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), nullable=False, unique=True)
    created = db.Column(db.DateTime, index=True, default=datetime.now)

    def __repr__(self):
        return "<Tag {}>".format(self.name)

class Movie(db.Model):
    __tablename__ = "movie"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    info = db.Column(db.Text)
    poster = db.Column(db.String(255), nullable=False)
    url = db.Column(db.String(255), nullable=False)
    star = db.Column(db.SmallInteger, default=0)
    region = db.Column(db.String(255))
    length = db.Column(db.Time)
    time_release = db.Column(db.Date)
    created = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    comments = db.relationship("Comment", backref="movie", lazy="dynamic")
    tags = db.relationship("Tag", secondary=tags, lazy='dynamic', backref=db.backref('movies', lazy='dynamic'))

    def __repr__(self):
        return "<Movie {}>".format(self.name)

auths = db.Table('auths',
                 db.Column('auth_id', db.Integer, db.ForeignKey('auth.id'), primary_key=True),
                 db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True)
                )

class Auth(db.Model):
    __tablename__ = "auth"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    created = db.Column(db.DateTime, index=True, default=datetime.now)

    def __repr__(self):
        return "<Auth {}>".format(self.name)

class Role(db.Model):
    __tablename__ = "role"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    created = db.Column(db.DateTime, index=True, default=datetime.now)
    auths = db.relationship('Auth', secondary=auths, lazy='dynamic', backref=db.backref('roles', lazy='dynamic'))
    admins = db.relationship("Admin", backref='role')

    def __repr__(self):
        return "<Role {}>".format(self.name)


class Admin(db.Model):
    __tablename__ = "admin"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    created = db.Column(db.DateTime, index=True, default=datetime.now)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    adminlogs = db.relationship('Adminlog', backref='admin')

    def __repr__(self):
        return "<Admin {}>".format(self.username)

    def hash_password(self):
        self.password = generate_password_hash(self.password)

    def verify_password(self, password):
        return check_password_hash(self.password, password)

class Adminlog(db.Model):
    __tablename__ = "adminlog"
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'))
    ip = db.Column(db.String(50))
    created = db.Column(db.DateTime, index=True, default=datetime.now)

    def __repr__(self):
        return "<Adminlog {}>".format(self.id)