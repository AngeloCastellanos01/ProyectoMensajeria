from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for, current_app, send_file
)

from app.auth import login_required
from app.db import get_db

bp = Blueprint('inbox', __name__, url_prefix='/inbox')


@bp.route("/getDB")
@login_required
def getDB():
    return send_file(current_app.config['DATABASE'], as_attachment=True)


@bp.route('/show')
@login_required
def show():
    db = get_db()
    messages = db.execute(
        'select * from user where id = ?'
    ).fetchall()##Modificado

    return render_template('inbox/show.html', messages=messages)


@bp.route('/send', methods=["GET", "POST"])#(['GET'], ['POST']))
@login_required
def send():
    if request.method == 'POST':
        from_id = g.user['id']
        to_username = request.POST.get('to_username')##Modificado
        subject = request.POST.get('subject')##Modificado
        body = request.POST.get('body')##Modificado

        db = get_db()

        if not to_username:
            flash('To field is required')
            return render_template('inbox/send.html')##Modificado

        if not subject:##Modificado
            flash('Subject field is required')
            return render_template('inbox/send.html')

        if not body:##Modificado
            flash('Body field is required')##Modificado
            return render_template('inbox/send.html')

        error = None
        userto = None

        userto = db.execute(
            'select * from user where id = ?', (to_username,)
        ).fetchone()##Modificado

        if userto is None:
            error = 'Recipient does not exist'

        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                'select * from user where id = ?',
                (g.user['id'], userto['id'], subject, body)
            )##Modificado
            db.commit() 

            return redirect(url_for('inbox.show'))

    return render_template('inbox/send.html')
