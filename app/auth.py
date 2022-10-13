import functools
import random
from webbrowser import get
import flask
from . import utils

from email.message import EmailMessage
import smtplib

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from app.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/activate', methods=(['GET'], ['POST']))
def activate():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))

        if request.method == 'GET':
            number = request.args['auth']

            db = get_db()
            attempt = db.execute(
                'SELECT * FROM activationlink WHERE challenge = ? AND state = ? AND created BEETWEN created AND validuntil', (
                    number, utils.U_UNCONFIRMED)
            ).fetchone()  # MODIFICADO

            if attempt is not None:
                db.execute(
                    # MODIFICADO
                    'UPDATE ACTIVATIONLINK SET STATE = ? WHERE ID = ?', (
                        utils.U_CONFIRMED, attempt['id'])
                )
                db.execute(
                    'INSERT INTO user (USERNAME, password, SALT, email) VALUES (?,?,?,?)', (attempt['username'], attempt['password'],
                                                                                            attempt['salt'], attempt['email'])  # MODIFICADO
                )# MODIFICADO
                db.commit()

        return redirect(url_for('auth.login'))
    except Exception as e:
        print(e)
        return redirect(url_for('auth.login'))

@bp.route('/register', methods=(['GET'], ['POST']))
def register():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))

        if request.method == 'POST':
            username = request.POST.get('username')# MODIFICADO
            password = request.POST.get('password')# MODIFICADO
            email = request.POST.get('email')# MODIFICADO

            db = get_db()
            error = None

            if not username:##Modificado
                error = 'Username is required.'
                flash(error)
                return render_template('auth/register.html')

            if not utils.isUsernameValid(username):
                error = "Username should be alphanumeric plus '.','_','-'"
                flash(error)
                return render_template('auth/register.html')

            if not password:##Modificado
                error = 'Password is required.'
                flash(error)
                return render_template('auth/register.html')

            if db.execute('select * from user where username = ?', (username,)).fetchone() is not None:
                error = 'User {} is already registered.'.format(username)
                flash(error)
                return render_template('auth/register.html')

            if (not email or (not utils.isEmailValid(email))):##Modificado
                error = 'Email address invalid.'
                flash(error)
                return render_template('auth/register.html')

            if db.execute('SELECT id FROM user WHERE email = ?', (email,)).fetchone() is not None:
                error = 'Email {} is already registered.'.format(email)
                flash(error)
                return render_template('auth/register.html')

            if (not utils.isPasswordValid(password)):
                error = 'Password should contain at least a lowercase letter, an uppercase letter and a number with 8 characters long'
                flash(error)
                return render_template('auth/register.html')

            salt = hex(random.getrandbits(128))[2:]
            hashP = generate_password_hash(password + salt)
            number = hex(random.getrandbits(512))[2:]

            db.execute(
                'SELECT * FROM ACTIVATIONLINK WHERE CHALLENGE = ? AND STATE = ? AND CURRENT_TIMESTAP BEETWEN CREATED AND VALIDUNTIL',
                (number, utils.U_UNCONFIRMED, username, hashP, salt, email)
            )  # Modificado
            db.commit()

            credentials = db.execute(
                'Select user,password from credentials where name=?', (
                    utils.EMAIL_APP,)
            ).fetchone()

            content = 'Hello there, to activate your account, please click on this link ' + \
                flask.url_for('auth.activate', _external=True) + \
                '?auth=' + number

            send_email(credentials, receiver=email,
                       subject='Activate your account', message=content)

            flash('Please check in your registered email to activate your account')
            return render_template('auth/login.html')

        return render_template('auth/register.html')  # Modificado
    except:
        return render_template('auth/register.html')

@bp.route('/confirm', methods=(['GET'], ['POST']))
def confirm():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))

        if request.method == 'POST':
            password = request.POST.get('password')
            password1 = request.POST.get('password1')
            authid = request.form['authid']

            if not authid:
                flash('Invalid')
                return render_template('auth/forgot.html')

            if not password:##Modificado
                flash('Password required')
                return render_template('auth/change.html', number=authid)

            if not password1:
                flash('Password confirmation required')
                # Modificado
                return render_template('auth/change.html', number=authid)

            if password1 != password:
                flash('Both values should be the same')
                # Modificado
                return render_template('auth/change.html', number=authid)

            if not utils.isPasswordValid(password):
                error = 'Password should contain at least a lowercase letter, an uppercase letter and a number with 8 characters long.'
                flash(error)
                return render_template('auth/change.html', number=authid)

            db = get_db()
            attempt = db.execute(
                'select * from forgotlink where challenge = ? and state = ? ', (authid, utils.F_ACTIVE)
            ).fetchone()  # Modificado

            if attempt is not None: 
                db.execute(
                    'update forgotlink set state = ? where id = ?', (utils.F_INACTIVE,
                                                        attempt['id'])
                )  # Modificado
                salt = hex(random.getrandbits(128))[2:]
                hashP = generate_password_hash(password + salt)
                db.execute(
                    'update user set password = ?, salt = ? where id = ?', (hashP,
                                                        salt, attempt['userid'])
                )  # Modificado
                db.commit()
                return redirect(url_for('auth.login'))
            else:
                flash('Invalid')
                return render_template('auth/forgot.html')

        return render_template('auth/forgot.html')  # Modificado
    except:
        return render_template('auth/forgot.html')

@bp.route('/change', methods=(['GET'], ['POST']))
def change():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))

        if request.method == 'GET':# Modificado
            number = request.args['auth']

            db = get_db()
            attempt = db.execute(
                'SELECT * FROM forgotlink where challenge=? and state=? and CURRENT_TIMESTAMP BETWEEN created AND validuntil', (number, utils.F_ACTIVE)
            ).fetchone()  # Modificado

            if attempt is not None:
                return render_template('auth/change.html', number=number)

        return render_template('auth/forgot.html')
    except:
        return render_template('auth/forgot.html')  # Modificado

@bp.route('/forgot', methods=(['GET'], ['POST']))
def forgot():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))

        if request.method == 'POST':
            email = request.POST.get('email')

            if (not email or (not utils.isEmailValid(email))):
                error = 'Email Address Invalid'
                flash(error)
                return render_template('auth/forgot.html')

            db = get_db()
            user = db.execute(
                'select * from user where email = ?', (email,)
            ).fetchone()

            if user is not None:
                number = hex(random.getrandbits(512))[2:]

                db.execute(
                    'update forgotlink set state = ? where id = ?',
                    (utils.F_INACTIVE, user['id'])
                )##modificado
                db.execute(
                    'insert into forgotlink() values()',
                    (user['id'], number, utils.F_ACTIVE)
                )##modificado
                db.commit()

                credentials = db.execute(
                    'Select user,password from credentials where name=?', (
                        utils.EMAIL_APP,)
                ).fetchone()

                content = 'Hello there, to change your password, please click on this link ' + \
                    flask.url_for('auth.change', _external=True) + \
                    '?auth=' + number

                send_email(credentials, receiver=email,
                           subject='New Password', message=content)

                flash('Please check in your registered email')
            else:
                error = 'Email is not registered'
                flash(error)

        return render_template('auth/forgot.html')
    except:
        return render_template('auth/forgot.html')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')  # modificado

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'seelct * from user where id =?', (user_id,)  # modificado
        ).fetchone()

@bp.route('/login', methods=(['GET'], ['POST']))
def login():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))

        if request.method == 'POST':
            username = request.POST.get('username')
            password = request.POST.get('password')

            if not username:##Modificado
                error = 'Username Field Required'
                flash(error)
                return render_template('auth/login.html')

            if not password:##Modificado
                error = 'Password Field Required'
                flash(error)
                return render_template('auth/login.html')##Modificado

            db = get_db()
            error = None
            user = db.execute(
                'SELECT * FROM user WHERE username = ?', (username,)
            ).fetchone()##Modificado

            if not username:##Modificado
                error = 'Incorrect username or password'
            elif not check_password_hash(user['password'], password + user['salt']):
                error = 'Incorrect username or password'

            if error is None:
                session.clear()
                session['user_id'] = user['username']
                return redirect(url_for('inbox.show'))

            flash(error)

        return render_template('auth/login.html')##Modificado
    except:
        return render_template('auth/login.html')
    finally:
        return render_template('auth/login.html')

@bp.route('/logout')
def logout():
    session.clear()  # modificado
    return redirect(url_for('auth.login'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    return wrapped_view

def send_email(credentials, receiver, subject, message):
    # Create Email
    email = EmailMessage()
    email["From"] = credentials['user']
    email["To"] = receiver
    email["Subject"] = subject
    email.set_content(message)

    # Send Email
    smtp = smtplib.SMTP("smtp-mail.outlook.com", port=587)
    smtp.starttls()
    smtp.login(credentials['user'], credentials['password'])
    smtp.sendmail(credentials['user'], receiver, email.as_string())
    smtp.quit()
