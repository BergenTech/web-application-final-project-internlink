from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_login import LoginManager, UserMixin
from flask_login import login_user, current_user, logout_user, login_required
from flask import Flask, render_template, request, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'Leo'
UPLOAD_FOLDER = 'path_to_upload_folder'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
db = SQLAlchemy(app)

class Intern(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    intern_email = db.Column(db.String(100), nullable=False, unique=True)
    graduation_year = db.Column(db.String(20), nullable=False)
    resume_path = db.Column(db.String(200), nullable=False)
    intern_password = db.Column(db.String(100), nullable=False)

    def get_id(self):
        return str(self.id)

    @property
    def is_active(self):
        return True

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False
    
    @login_manager.user_loader
    def load_user(user_id):
        return Intern.query.get(int(user_id))
    
class Organization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    organization_name = db.Column(db.String(100), nullable=False)
    org_email = db.Column(db.String(100), nullable=False, unique=True)
    topic = db.Column(db.String(100), nullable=False)
    day_hours = db.Column(db.String(100), nullable=False)
    paid_unpaid = db.Column(db.String(20), nullable=False)
    requirements = db.Column(db.Text, nullable=False)
    org_password = db.Column(db.String(100), nullable=False)

    def get_id(self):
        return str(self.id)

    @property
    def is_active(self):
        return True

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False
    
    @login_manager.user_loader
    def load_user(user_id):
        return Organization.query.get(int(user_id))

with app.app_context():
    db.create_all()

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    flash('You have been logged out successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    return render_template('register.html')

@app.route('/register/intern', methods=['GET', 'POST'])
def register_intern():
    if request.method == 'POST':
        full_name = request.form['full_name']
        intern_email = request.form['intern_email']
        graduation_year = request.form['graduation_year']
        resume_file = request.files['resume']
        intern_password = request.form['intern_password']
        intern_confirm_password = request.form['intern_confirm_password']

        if intern_password != intern_confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('register_intern'))

        hashed_password = generate_password_hash(intern_password)
        resume_path = 'path_to_upload_folder/' + resume_file.filename

        new_intern = Intern(full_name=full_name, intern_email=intern_email, graduation_year=graduation_year, resume_path=resume_path, intern_password=hashed_password)
        resume_file.save(resume_path)

        db.session.add(new_intern)
        db.session.commit()

        flash('Intern registered successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('register_intern.html')

@app.route('/register/organization', methods=['GET', 'POST'])
def register_organization():
    if request.method == 'POST':
        organization_name = request.form['organization_name']
        org_email = request.form['org_email']
        topic = request.form['topic']
        day_hours = request.form['day_hours']
        paid_unpaid = request.form['paid_unpaid']
        requirements = request.form['requirements']
        org_password = request.form['org_password']
        org_confirm_password = request.form['org_confirm_password']

        if org_password != org_confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('register_organization'))

        hashed_password = generate_password_hash(org_password)

        new_organization = Organization(organization_name=organization_name, org_email=org_email, topic=topic, day_hours=day_hours, paid_unpaid=paid_unpaid, requirements=requirements, org_password=hashed_password)
        db.session.add(new_organization)
        db.session.commit()

        flash('Organization registered successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('register_organization.html')

# @app.route('/registerold', methods=['GET', 'POST'])
# def registerold():
#     if request.method == 'POST':
#         user_type = request.form['user_type']

#         if user_type == 'intern':
#             full_name = request.form['full_name']
#             email = request.form['email']
#             graduation_year = request.form['graduation_year']
#             resume_file = request.files['resume']
#             intern_password = request.form['intern_password']
#             intern_confirm_password = request.form['intern_confirm_password']

#             if intern_password != intern_confirm_password:
#                 flash('Passwords do not match!', 'error')
#                 return redirect(url_for('register'))

#             hashed_password = generate_password_hash(intern_password)
#             resume_path = 'path_to_upload_folder/' + resume_file.filename

#             new_intern = Intern(full_name=full_name, email=email, graduation_year=graduation_year, resume_path=resume_path, intern_password=hashed_password)
#             resume_file.save(resume_path)

#             db.session.add(new_intern)
#             db.session.commit()

#         elif user_type == 'organization':
#             organization_name = request.form['organization_name']
#             email = request.form['email']
#             topic = request.form['topic']
#             day_hours = request.form['day_hours']
#             paid_unpaid = request.form['paid_unpaid']
#             requirements = request.form['requirements']
#             org_password = request.form['org_password']
#             org_confirm_password = request.form['org_confirm_password']

#             if org_password != org_confirm_password:
#                 flash('Passwords do not match!', 'error')
#                 return redirect(url_for('register'))

#             hashed_password = generate_password_hash(org_password)

#             new_organization = Organization(organization_name=organization_name, email=email, topic=topic, day_hours=day_hours, paid_unpaid=paid_unpaid, requirements=requirements, org_password=hashed_password)
#             db.session.add(new_organization)
#             db.session.commit()

#         flash('User registered successfully!', 'success')
#         return redirect(url_for('index'))

#     return render_template('registerold.html')

@app.route("/")
def index():
    return render_template("home.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        intern_user = Intern.query.filter_by(intern_email=email).first()
        if intern_user and check_password_hash(intern_user.intern_password, password):
            login_user(intern_user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('profile_intern'))

        organization_user = Organization.query.filter_by(org_email=email).first()
        if organization_user and check_password_hash(organization_user.org_password, password):
            login_user(organization_user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('profile_organization'))

        flash('Invalid email or password. Please try again.', 'error')
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route("/view_jobs")
def view_jobs():
    return render_template("view_jobs.html")

@app.route("/profile/intern")
@login_required
def profile_intern():
    if current_user and isinstance(current_user, Intern):
        user = current_user
        user_type = 'Intern'
        return render_template("profile.html", user=user, user_type=user_type)
    else:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('index'))

@app.route("/profile/organization")
@login_required
def profile_organization():
    if current_user and isinstance(current_user, Organization):
        user = current_user
        user_type = 'Organization'
        return render_template("profile.html", user=user, user_type=user_type)
    else:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(debug=True)