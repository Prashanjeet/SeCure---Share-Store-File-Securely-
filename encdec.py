import divider as dv
import tools
from flask import render_template
import encrypter as enc
import decrypter as dec
import restore as rst
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

def start_encryption():
	dv.divide()
	tools.empty_folder('uploads')
	enc.encrypter()
	return render_template('success.html', name = current_user.username)

def start_decryption():
	dec.decrypter()
	tools.empty_folder('key')
	rst.restore()
	return render_template('restore_success.html')
