#Libraries Required
import os
from flask import Flask, render_template, redirect, url_for, request, send_from_directory, send_file
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from sqlalchemy import create_engine

from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename

# Required Custom Scripts
import tools
import divider as dv
import encrypter as enc
import decrypter as dec
import restore as rst

UPLOAD_FOLDER = './uploads/'
UPLOAD_KEY = './key/'
ALLOWED_EXTENSIONS = set(['png'])

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ThisIsSupposedToBeSecret!'
db_uri = 'sqlite:////newdataset.db'
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
engine = create_engine(db_uri)

app.config['UPLOAD_KEY'] = UPLOAD_KEY
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def allowed_file(filename):
	return '.' in filename and \
		filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def start_encryption(txt):
	file_data = file_contents.query.filter_by(name = txt).first()

	if file_data:
		fp = open(UPLOAD_FOLDER + txt, "wb")
		fp.write(file_data.data)
		fp.close()
		dv.divide(txt)
		tools.empty_folder('uploads')
		enc.encrypter(txt)
		return render_template('success.html', name = current_user.username)
	else:
		return render_template('exception.html', message = 'File not found')

def start_decryption(fname):
	dec.decrypter(fname)
	tools.empty_folder('key')
	rst.restore(fname)
	return render_template('restore_success.html')

@app.route('/return-key/')
@login_required
def return_key():
	list_directory = tools.list_dir('key')
	filename = './key/' + list_directory[0]

	return send_file(filename, as_attachment=True)

@app.route('/return-file/')
@login_required
def return_file():
	list_directory = tools.list_dir('restored_file')
	filename = './restored_file/' + list_directory[0]
	return send_file(filename, attachment_filename=list_directory[0], as_attachment=True)

@app.route('/download/')
@login_required
def downloads():
	return render_template('download.html', name = current_user.username)

@app.route('/upload')
@login_required
def call_page_upload():
	return render_template('upload.html')

@app.route('/home')
@login_required
def back_home():
	tools.empty_folder('key')
	tools.empty_folder('restored_file')
	result = engine.execute('Select * from file_contents')
	file_names = []
	keys = []
	for id in result:
		file_names.append(id[1])
	return render_template('dashboard.html', name=current_user.username, data = file_names)

@app.route('/data', methods=['GET', 'POST'])
@login_required
def upload_file():
	tools.empty_folder('uploads')
	if request.method == 'POST':
		# check if the post request has the file part
		if 'file' not in request.files:
			flash('No file part')
			return redirect(request.url)
		file = request.files['file']
		# if user does not select file, browser also
		# submit a empty part without filename
		if file.filename == '':
			flash('No selected file')
			return 'NO FILE SELECTED'
		if file:
			file_data = file_contents.query.filter_by(name = file.filename).first()
			if file_data:
				return '<h1> File already Found in Database !!</h1>'
			else :
				newFile = file_contents(name = file.filename, data = file.read())
				db.session.add(newFile)
				db.session.commit()
				return '<h1> File Uploaded successfully!!</h1>'
		return 'Invalid File Format !'

@app.route('/download_data', methods=['GET', 'POST'])
@login_required
def upload_key():
	tools.empty_folder('key')
	if request.method == 'POST':
		# check if the post request has the file part
		if 'file' not in request.files:
			flash('No file part')
			return redirect(request.url)
		file = request.files['file']
		# if user does not select file, browser also
		# submit a empty part without filename
		if file.filename == '':
			flash('No selected file')
			return 'NO FILE SELECTED'
		if file and allowed_file(file.filename):
			filename = secure_filename(file.filename)
			name = os.path.basename(file.filename)
			(fname, ext) = os.path.splitext(name)
			file.save(os.path.join(app.config['UPLOAD_KEY'], file.filename))

			return start_decryption(fname)
		return 'Invalid File Format !'



bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50))
    password = db.Column(db.String(80))

class file_contents(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(300))
    data = db.Column(db.LargeBinary)

class requests(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(300))
    file_id = db.Column(db.Integer, db.ForeignKey('file_contents.id'))
    user_Name = db.Column(db.String, db.ForeignKey('user.id'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
			# for other than admin users
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
				# for admin only
                if form.username.data == 'admin':
					return redirect(url_for('dashboard'))
				# Else the login credentials belong to End User
                return redirect(url_for('user_panel'))

        return render_template('exception.html', message = "Invalid LogIn Credentials")

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
	try:
	    form = RegisterForm()

	    if form.validate_on_submit():
	        hashed_password = generate_password_hash(form.password.data, method='sha256')
	        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
	        db.session.add(new_user)
	        db.session.commit()

        	return render_template('exception.html', message = "New user has been created!")
	    return render_template('signup.html', form=form)
	except:
		return render_template('exception.html', message = "The Username is Already Taken try another!")

@app.route('/dashboard')
@login_required
def dashboard():
	file_contents = engine.execute('Select * from file_contents')
	file_names = []
	for id in file_contents:
		file_names.append(id[1])
	rqst = engine.execute('SELECT name, user_Name FROM requests')
	if rqst :
		return render_template('dashboard.html', name=current_user.username, data = file_names, req = rqst)
	else:
		return render_template('dashboard.html', name=current_user.username, data = file_names)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/user_panel')
@login_required
def user_panel():
	result = engine.execute('Select * from file_contents')
	_list = []
	for id in result:
		_list.append(id[1])
	return render_template('user_panel.html', name=current_user.username, data = _list)


@app.route('/gen-key')
@login_required
def generate_key():
	result = engine.execute('Select * from file_contents')
	_list = []
	for id in result:
		_list.append(id[1])
	return render_template('generate_key.html', data = _list)

# ------------------------ End Of User panel -----------------------------------
# ------------------------ Start Of End User modules -----------------------------------

@app.route('/request-file/', methods=['POST'])
@login_required
def _return():
	txt = request.form['text']
	file_data = file_contents.query.filter_by(name = txt).first()
	if file_data:
		name = file_data.name
		id = file_data.id
		nme = name.encode('ascii', 'ignore')
		#return send_file(BytesIO(file_data.data), attachment_filename= nme, as_attachment=True)
		newReq = requests(name = txt, file_id = id, user_Name = current_user.username)
		db.session.add(newReq)
		db.session.commit()
		return "<h1>Your Request Submitted</h1>"
	else:
		return "<h1>Couldn't found the file you're looking for!!</h1>"

@app.route('/generate-key', methods=['POST'])
@login_required
def genkey():
	txt = request.form['text']
	if txt :
		return start_encryption(txt)
	else:
		return render_template('exception.html', message = 'File not found')

# ------------------------ End Of End User modules -----------------------------------

if __name__ == '__main__':
    app.run(debug=True)
