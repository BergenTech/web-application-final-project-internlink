from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_login import LoginManager, UserMixin
from flask_login import login_user, current_user, logout_user, login_required
from flask import Flask, render_template, request, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
import os
from werkzeug.security import generate_password_hash, check_password_hash
import csv

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

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_name = db.Column(db.String(100), nullable=False)
    admin_email = db.Column(db.String(100), nullable=False, unique=True)
    admin_password = db.Column(db.String(100), nullable=False)

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
        return Admin.query.get(int(user_id))

class Organization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(100), nullable=False)
    website = db.Column(db.String(100), nullable=False)
    street_address = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(100), nullable=False)
    zip_code = db.Column(db.String(20), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    internship_mentor = db.Column(db.String(100), nullable=False)
    internship_topic = db.Column(db.String(100), nullable=False)

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
    
class Intern(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    intern_name = db.Column(db.String(100), nullable=False)
    intern_email = db.Column(db.String(100), nullable=False, unique=True)
    graduation_year = db.Column(db.String(100), nullable=False)
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

with app.app_context():
    db.create_all()

def import_csv_data():
    with app.app_context():
        with open('static/internships.csv', 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                new_organization = Organization(
                    company_name=row['COMPANY NAME'],
                    website=row['WEBSITE'],
                    street_address=row['STREET ADDRESS'],
                    city=row['CITY'],
                    state=row['STATE'],
                    zip_code=row['ZIP'],
                    phone=row['PHONE'],
                    email=row['EMAIL'],
                    internship_mentor=row['INTERNSHIP MENTOR'],
                    internship_topic=row['INTERNSHIP TOPIC']
                )
                db.session.add(new_organization)
            db.session.commit()

import_csv_data()

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    logout_user()
    flash('You have been logged out successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/contact')
def contact():
    pass

@app.route('/messages')
def messages():
    organization_messages = [
        {"from": "Organization Name 1", "message": "Sample message from Organization 1."},
        {"from": "Organization Name 2", "message": "Sample message from Organization 2."}
    ]

    intern_messages = [
        {"from": "Intern Name 1", "message": "Sample message from Intern 1."},
        {"from": "Intern Name 2", "message": "Sample message from Intern 2."}
    ]

    return render_template('messages.html', organization_messages=organization_messages, intern_messages=intern_messages)

@app.route('/register', methods=['GET', 'POST'])
def register():
    return render_template('register.html')

@app.route('/register/intern', methods=['GET', 'POST'])
def register_intern():
    if request.method == 'POST':
        intern_name = request.form['intern_name']
        intern_email = request.form['intern_email']
        graduation_year = request.form['graduation_year']
        intern_password = request.form['intern_password']
        intern_confirm_password = request.form['intern_confirm_password']

        if intern_password != intern_confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('register_intern'))

        hashed_password = generate_password_hash(intern_password)

        new_intern = Intern(intern_name=intern_name, intern_email=intern_email, graduation_year=graduation_year, intern_password=hashed_password)
        db.session.add(new_intern)
        db.session.commit()

        flash('Intern registered successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('register_intern.html')

@app.route('/add_organization', methods=['GET', 'POST'])
@login_required
def add_organization():
    if request.method == 'POST':
        organization_name = request.form['organization_name']
        org_email = request.form['org_email']
        topic = request.form['topic']
        day_hours = request.form['day_hours']
        paid_unpaid = request.form['paid_unpaid']
        requirements = request.form['requirements']

        new_organization = Organization(organization_name=organization_name, org_email=org_email, topic=topic, day_hours=day_hours, paid_unpaid=paid_unpaid, requirements=requirements)
        db.session.add(new_organization)
        db.session.commit()

        flash('Organization added successfully!', 'success')
        return render_template('add_organization.html')
    return render_template('add_organization.html')

@app.route('/register/admin', methods=['GET', 'POST'])
def register_admin():
    if request.method == 'POST':
        admin_name = request.form['admin_name']
        admin_email = request.form['admin_email']
        admin_password = request.form['admin_password']
        admin_confirm_password = request.form['admin_confirm_password']

        if admin_password != admin_confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('register_admin'))

        hashed_password = generate_password_hash(admin_password)

        new_admin = Admin(admin_name=admin_name, admin_email=admin_email, admin_password=hashed_password)
        db.session.add(new_admin)
        db.session.commit()

        flash('Intern registered successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('register_admin.html')

@app.route("/")
def index():
    if session.get('user_id') and session.get('user_type') == 'Intern':
        user_id = session['user_id']
        intern = Intern.query.get(user_id)
        return render_template("home.html", user=intern, user_type='Intern')
    elif session.get('user_id') and session.get('user_type') == 'Admin':
        user_id = session['user_id']
        admin = Admin.query.get(user_id)
        return render_template("home.html", user=admin, user_type='Admin')
    else:
        return render_template("home.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        intern_user = Intern.query.filter_by(intern_email=email).first()
        if intern_user and check_password_hash(intern_user.intern_password, password):
            session['user_id'] = intern_user.id
            session['user_type'] = 'Intern'
            flash('Logged in successfully!', 'success')
            return redirect(url_for('profile_intern'))
        
        admin_user = Admin.query.filter_by(admin_email=email).first()
        if admin_user and check_password_hash(admin_user.admin_password, password):
            session['user_id'] = admin_user.id
            session['user_type'] = 'Admin'
            flash('Logged in successfully!', 'success')
            return redirect(url_for('profile_admin'))

        flash('Invalid email or password. Please try again.', 'error')
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route("/view_jobs")
def view_jobs():
    organizations = Organization.query.all()
    return render_template("view_jobs.html", organizations=organizations)

@app.route("/profile/intern")
def profile_intern():
    if session.get('user_id') and session.get('user_type') == 'Intern':
        user_id = session['user_id']
        intern = Intern.query.get(user_id)
        login_user(intern)
        return render_template("profile.html", user=intern, user_type='Intern')
    else:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('index'))
    
@app.route("/profile/admin")
def profile_admin():
    if session.get('user_id') and session.get('user_type') == 'Admin':
        user_id = session['user_id']
        admin = Admin.query.get(user_id)
        login_user(admin)
        return render_template("profile.html", user=admin, user_type='Admin')
    else:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('index'))
    
@app.route('/edit_profile', methods=['POST'])
def edit_profile():
    user_type = session.get('user_type')
    if user_type == 'Intern':
        user = Intern.query.get(session['user_id'])
        user.intern_name = request.form.get('intern_name', user.intern_name)
        user.intern_email = request.form.get('intern_email', user.intern_email)
        user.graduation_year = request.form.get('graduation_year', user.graduation_year)
    elif user_type == 'Organization':
        user = Organization.query.get(session['user_id'])
        user.organization_name = request.form.get('organization_name', user.organization_name)
        user.org_email = request.form.get('org_email', user.org_email)
        user.topic = request.form.get('topic', user.topic)
        user.day_hours = request.form.get('day_hours', user.day_hours)
        user.paid_unpaid = request.form.get('paid_unpaid', user.paid_unpaid)
        user.requirements = request.form.get('requirements', user.requirements)
    elif user_type == 'Admin':
        user = Admin.query.get(session['user_id'])
        user.admin_name = request.form.get('admin_name', user.admin_name)
        user.admin_email = request.form.get('admin_email', user.admin_email)
    db.session.commit()
    flash('Profile updated successfully!', 'success')
    return redirect(url_for(f'profile_{user_type.lower()}'))

if __name__ == "__main__":
    app.run(debug=True)