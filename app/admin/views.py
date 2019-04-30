import os
from . import admin_bp 
from app import db, app
from flask import url_for, render_template, flash, session, redirect, g, request
from werkzeug.urls import url_parse
from werkzeug.utils import secure_filename
from app.models import Admin, Adminlog, Tag, Movie, Auth, Role, User
from .forms import LoginForm, MovieForm, TagForm, AuthForm, RoleForm
from functools import wraps

def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.admin is None:
            return redirect(url_for('admin_bp.login', next=request.url))
        return view(**kwargs)
    return wrapped_view

@admin_bp.before_app_request
def load_logged_in_admin():
    admin_id = session.get('admin_id')
    if admin_id is None:
        g.admin = None
    else:
        g.admin = Admin.query.get_or_404(admin_id)

#--------------------------------------------------------------------------------------#
@admin_bp.route("/login/", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        admin = Admin.query.filter_by(username=form.username.data).first()
        if admin is None or not admin.verify_password(form.password.data):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('admin_bp.login'))
        session.clear()
        session['admin'] = form.username.data
        session['admin_id'] = admin.id
        adminlog = Adminlog(admin_id=admin.id, ip=request.remote_addr)
        db.session.add(adminlog)
        db.session.commit()
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('admin_bp.index')
        return redirect(next_page)
    return render_template('admin/login.html', form=form)

@admin_bp.route("/logout/")
def logout():
    session.clear()
    return redirect(url_for('admin_bp.login'))
#--------------------------------------------------------------------------------------#

@admin_bp.route('/')
@login_required
def index():
    return render_template("admin/dashboard.html")

#--------------------------------------------------------------------------------------#

@admin_bp.route('/auth/add/', methods=['GET', 'POST'])
@login_required
def add_auth():
    form = AuthForm()
    if form.validate_on_submit():
        isExist = Auth.query.filter_by(name=form.name.data).count()
        if isExist:
            flash("Auth have existed. Please try again", "danger")
            return redirect(url_for("admin_bp.add_auth")) 
        auth = Auth(name=form.name.data)
        db.session.add(auth)
        db.session.commit()
        flash("Auth was added", "success")
        return redirect(url_for("admin_bp.list_auth", page=1))
    return render_template("admin/add_auth.html", form=form)

@admin_bp.route('/auth/list/<int:page>', methods=['GET'])
@login_required
def list_auth(page):
    auths = Auth.query.order_by(Auth.created.desc()).paginate(page=page, per_page=10)
    title = "Auth"
    return render_template("admin/list.html", data=auths, title=title, type='auth')

@admin_bp.route('/auth/delete/<int:id>', methods=['GET'])
@login_required
def delete_auth(id):
    auth = Auth.query.get_or_404(id)
    db.session.delete(auth)
    db.session.commit()
    flash("Auth was deleted", "success")
    return redirect(url_for('admin_bp.list_auth', page=1))

@admin_bp.route('/auth/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_auth(id):
    auth = Auth.query.get_or_404(id)
    form = AuthForm()
    if form.validate_on_submit():
        isExist = Auth.query.filter_by(name=form.name.data).count()
        if isExist:
            flash("Auth have existed. Please try again", "danger")
            return redirect(url_for("admin_bp.edit_auth", id=auth.id)) 
        auth.name = form.name.data
        db.session.commit()
        flash("Auth was edited", "success")
        return redirect(url_for("admin_bp.list_auth", page=1))
    elif request.method == 'GET':
        form.submit.label.text = "Edit Auth"
        form.name.data = auth.name
    return render_template("admin/add_auth.html", form=form)

#--------------------------------------------------------------------------------------#

#--------------------------------------------------------------------------------------#

@admin_bp.route('/tag/add/', methods=['GET', 'POST'])
@login_required
def add_tag():
    form = TagForm()
    if form.validate_on_submit():
        isExist = Tag.query.filter_by(name=form.name.data).count()
        if isExist:
            flash("Tag have existed. Please try again", "danger")
            return redirect(url_for("admin_bp.add_tag")) 
        tag = Tag(name=form.name.data)
        db.session.add(tag)
        db.session.commit()
        flash("Tag was added", "success")
        return redirect(url_for("admin_bp.list_tag", page=1))
    return render_template("admin/add_tag.html", form=form)

@admin_bp.route('/tag/list/<int:page>', methods=['GET'])
@login_required
def list_tag(page):
    tags = Tag.query.order_by(Tag.created.desc()).paginate(page=page, per_page=10)
    title = "Tag"
    return render_template("admin/list.html", data=tags, title=title, type='tag')

@admin_bp.route('/tag/delete/<int:id>', methods=['GET'])
@login_required
def delete_tag(id):
    tag = Tag.query.get_or_404(id)
    db.session.delete(tag)
    db.session.commit()
    flash("Tag was deleted", "success")
    return redirect(url_for('admin_bp.list_tag', page=1))

@admin_bp.route('/tag/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_tag(id=None):
    tag = Tag.query.get_or_404(id)
    form = TagForm()
    if form.validate_on_submit():
        isExist = Tag.query.filter_by(name=form.name.data).count()
        if isExist:
            flash("Tag have existed. Please try again", "danger")
            return redirect(url_for("admin_bp.edit_tag", id=tag.id)) 
        tag.name = form.name.data
        db.session.commit()
        flash("Tag was edited", "success")
        return redirect(url_for("admin_bp.list_tag"))
    elif request.method == 'GET':
        form.submit.label.text = "Edit Tag"
        form.name.data = tag.name
    return render_template("admin/add_tag.html", form=form)

#--------------------------------------------------------------------------------------#

@admin_bp.route('/movie/upload/', methods=['GET', 'POST'])
@login_required
def upload_movie():
    form = MovieForm()
    form.tag.choices = [(t.id, t.name) for t in Tag.query.all()]
    print(form.validate_on_submit())
    if form.validate_on_submit():
        tags = [Tag.query.get_or_404(id) for id in form.tag.data]
        movie = Movie(
            name=form.name.data,
            info=form.desc.data,
            poster=form.poster.data,
            url=form.source.data,
            region=form.country.data,
            length=form.length.data,
            time_release=form.release.data,
            tags=tags
        )
        print(movie)
        db.session.add(movie)
        db.session.commit()
        flash("Movie was upload", "success")
        return redirect(url_for("admin_bp.index"))
    return render_template("admin/upload_movie.html", form=form)

@admin_bp.route('/movie/list/<int:page>', methods=['GET'])
@login_required
def list_movie(page):
    movies = Movie.query.order_by(Movie.created.desc()).paginate(page=page, per_page=10)
    title = "Movie"
    return render_template("admin/list.html", data=movies, title=title, type='movie')

@admin_bp.route('/movie/delete/<int:id>', methods=['GET'])
@login_required
def delete_movie(id):
    movie = Movie.query.get_or_404(id)
    db.session.delete(movie)
    db.session.commit()
    flash("Movie was deleted", "success")
    return redirect(url_for('admin_bp.list_movie', page=1))

@admin_bp.route('/movie/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_movie(id=None):
    movie = Movie.query.get_or_404(id)
    form = MovieForm()
    form.tag.choices = [(t.id, t.name) for t in Tag.query.all()]
    if form.validate_on_submit():
        isExist = Movie.query.filter_by(name=form.name.data).count()
        if isExist:
            flash("Movie have existed. Please try again", "danger")
            return redirect(url_for("admin_bp.edit_Movie", id=movie.id)) 
        movie.name = form.name.data
        db.session.commit()
        flash("Movie was edited", "success")
        return redirect(url_for("admin_bp.list_movie", page=1))
    elif request.method == 'GET':
        form.upload.label.text = "Edit Movie"
        form.name.data = movie.name
        form.country.data = movie.region
        form.desc.data = movie.info
        form.length.data = movie.length
        form.poster.data = movie.poster
        form.source.data = movie.url
        form.release.data = movie.time_release
        form.tag.data = [tag.id for tag in movie.tags]
    return render_template("admin/upload_movie.html", form=form)

@admin_bp.route('/role/add/', methods=['GET', 'POST'])
@login_required
def add_role():
    form = RoleForm()
    form.auth.choices = [(a.id, a.name) for a in Auth.query.all()]
    if form.validate_on_submit():
        isExist = Role.query.filter_by(name=form.name.data).count()
        if isExist:
            flash("Role have existed. Please try again", "danger")
            return redirect(url_for("admin_bp.add_tag")) 
        auths = [Auth.query.get_or_404(id) for id in form.auth.data]
        role = Role(name=form.name.data,
                   auths=auths)
        db.session.add(role)
        db.session.commit()
        flash("Role was added", "success")
        return redirect(url_for("admin_bp.list_role"))
    return render_template("admin/add_role.html", form=form)

@admin_bp.route('/role/list/<int:page>', methods=['GET'])
@login_required
def list_role(page):
    roles = Role.query.order_by(Role.created.desc()).paginate(page=page, per_page=10)
    title = "role"
    return render_template("admin/list.html", data=roles, title=title, type='role')

@admin_bp.route('/role/delete/<int:id>', methods=['GET'])
@login_required
def delete_role(id):
    role = Role.query.get_or_404(id)
    db.session.delete(role)
    db.session.commit()
    flash("Role was deleted", "success")
    return redirect(url_for('admin_bp.list_role', page=1))

@admin_bp.route('/role/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_role(id=None):
    role = Role.query.get_or_404(id)
    form = RoleForm()
    form.auth.choices = [(a.id, a.name) for a in Auth.query.all()]
    if form.validate_on_submit():
        isExist = role.query.filter_by(name=form.name.data).count()
        if isExist:
            flash("role have existed. Please try again", "danger")
            return redirect(url_for("admin_bp.edit_role", id=role.id)) 
        role.name = form.name.data
        db.session.commit()
        flash("Role was edited", "success")
        return redirect(url_for("admin_bp.list_role", page=1))
    elif request.method == 'GET':
        form.submit.label.text = "Edit role"
        form.name.data = role.name
        form.auth.data = [auth.id for auth in role.auths]
        print([auth.id for auth in role.auths])
    return render_template("admin/add_role.html", form=form)

@admin_bp.route('/user/list/<int:page>', methods=['GET'])
@login_required
def list_user(page):
    users = User.query.order_by(User.created.desc()).paginate(page=page, per_page=10)
    title = "User"
    return render_template("admin/list.html", data=users, title=title, type='user')

@admin_bp.route('/user/delete/<int:id>', methods=['GET'])
@login_required
def delete_user(id):
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    flash("User was deleted", "success")
    return redirect(url_for('admin_bp.list_user', page=1))

@admin_bp.route('/admin/list/<int:page>', methods=['GET'])
@login_required
def list_admin(page):
    admins = Admin.query.order_by(Admin.created.desc()).paginate(page=page, per_page=10)
    title = "Admin"
    return render_template("admin/list.html", data=admins, title=title, type='admin')

@admin_bp.route('/admin/delete/<int:id>', methods=['GET'])
@login_required
def delete_admin(id):
    admin = Admin.query.get_or_404(id)
    db.session.delete(admin)
    db.session.commit()
    flash("Admin was deleted", "success")
    return redirect(url_for('admin_bp.list_admin', page=1))