from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import csv
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy.exc import IntegrityError
from flask_migrate import Migrate
import datetime
from dotenv import load_dotenv

# environment variables
load_dotenv()

app = Flask(__name__)
# Calculate the next year
next_year = datetime.datetime.now().year + 1
next_year_suffix = str(next_year)[-2:]


login_manager = LoginManager(app)
login_manager.login_view = 'login'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png', 'gif'}
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
db = SQLAlchemy(app)
migrate = Migrate(app, db)



class Admin(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    admin_name = db.Column(db.String(100), nullable=False)
    admin_email = db.Column(db.String(100), nullable=False)
    admin_password = db.Column(db.String(100), nullable=False)
    registration_verified = db.Column(db.Boolean, default=False)

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
    @property
    def is_admin(self):
        return True  # Since this is the Admin class, always return True
    
@login_manager.user_loader
def load_user(user_id):
    if session.get('user_type') == 'Intern':
        return Intern.query.get(int(user_id))
    elif session.get('user_type') == 'Admin':
        return Admin.query.get(int(user_id))
    elif session.get('user_type') == 'Organization':
        return Organization.query.get(int(user_id))


class DataImportFlag(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    def get_id(self):
        return str(self.id)

class Organization(db.Model, UserMixin):
    __tablename__ = 'organization'
    __table_args__ = {'extend_existing': True}

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
    major = db.Column(db.String(100))
    approval_limit = db.Column(db.Integer, default=5)
    approved_claims_count = db.Column(db.Integer, default=0)
    claims = db.relationship('Claim', backref='organization', lazy=True)

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

class Claim(db.Model):
    __tablename__ = 'claim'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(50), default='Pending')
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    intern_id = db.Column(db.Integer, db.ForeignKey('intern.id'), nullable=False)


class InternOrganization(db.Model):
    __tablename__ = 'intern_organization'
    intern_id = db.Column(db.Integer, db.ForeignKey('intern.id'), primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), primary_key=True)
    status = db.Column(db.String(50), default='Pending')
    
    intern = db.relationship('Intern', backref=db.backref('intern_organizations', lazy=True))
    organization = db.relationship('Organization', backref=db.backref('intern_organizations', lazy=True))

class Intern(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    intern_name = db.Column(db.String(100), nullable=False)
    intern_email = db.Column(db.String(100), nullable=False, unique=True)
    graduation_year = db.Column(db.String(100), nullable=False)
    intern_password = db.Column(db.String(100), nullable=False)
    major = db.Column(db.String(100), nullable=False)
    profile_photo = db.Column(db.String(100))
    resume = db.Column(db.String(100))
    email_verified = db.Column(db.Boolean, default=False)
    claimed_jobs = db.relationship('Organization', secondary='intern_organization', backref='interns')
    claims = db.relationship('Claim', backref='intern', lazy=True)

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

with app.app_context():
    db.create_all()

def import_csv_data():
    with app.app_context():
        if not DataImportFlag.query.first():
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
                        internship_topic=row['INTERNSHIP TOPIC'],
                        major=row['MAJORS']
                    )
                    db.session.add(new_organization)
                db.session.commit()

            data_import_flag = DataImportFlag()
            db.session.add(data_import_flag)
            db.session.commit()

# import_csv_data()


@app.route('/admin/manage_claims')
@login_required
def manage_claims():
    if current_user.is_admin:
        organization_filter = request.args.get('organization_filter')
        intern_filter = request.args.get('intern_filter')

        claims_query = InternOrganization.query

        if organization_filter:
            claims_query = claims_query.filter_by(organization_id=organization_filter)

        if intern_filter:
            claims_query = claims_query.filter_by(intern_id=intern_filter)

        claims = claims_query.all()
        organizations = Organization.query.all()
        interns = Intern.query.all()

        return render_template('manage_claims.html', claims=claims, organizations=organizations, interns=interns)
    else:
        flash('Access Denied', 'danger')
        return redirect(url_for('index'))




@app.route('/admin/approve_claim/<int:intern_id>/<int:organization_id>', methods=['POST'])
@login_required
def approve_claim(intern_id, organization_id):
    if current_user.is_admin:
        claim = InternOrganization.query.filter_by(intern_id=intern_id, organization_id=organization_id).first()
        organization = Organization.query.get_or_404(organization_id)
        if organization.approved_claims_count < organization.approval_limit:
            claim.status = 'Approved'
            organization.approved_claims_count += 1
            db.session.commit()
            flash('Claim approved successfully', 'success')
        else:
            flash('Approval limit reached for this organization', 'danger')
        return redirect(url_for('manage_claims'))
    else:
        flash('Access Denied', 'danger')
        return redirect(url_for('index'))

@app.route('/admin/deny_claim/<int:intern_id>/<int:organization_id>', methods=['POST'])
@login_required
def deny_claim(intern_id, organization_id):
    if current_user.is_admin:
        claim = InternOrganization.query.filter_by(intern_id=intern_id, organization_id=organization_id).first()
        claim.status = 'Denied'
        db.session.commit()
        flash('Claim denied successfully', 'success')
        return redirect(url_for('manage_claims'))
    else:
        flash('Access Denied', 'danger')
        return redirect(url_for('index'))





@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    logout_user()
    flash('You have been logged out successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/claim_job/<int:organization_id>', methods=['POST'])
@login_required
def claim_job(organization_id):
    if request.method == 'POST':
        intern_id = current_user.id
        intern = Intern.query.get(intern_id)
        organization = Organization.query.get(organization_id)
        if intern and organization:
            if len(intern.claimed_jobs) < 5:
                if organization not in intern.claimed_jobs:
                    new_claim = InternOrganization(intern_id=intern_id, organization_id=organization_id, status='Requested')
                    db.session.add(new_claim)
                    db.session.commit()
                    flash('You have successfully claimed this job!', 'success')
                else:
                    flash('You have already claimed this job.', 'info')
            else:
                flash('You can only claim up to 5 jobs.', 'error')
        else:
            flash('Error: Unable to claim job.', 'error')
    return redirect(url_for('view_jobs'))



@app.route('/delete_profile/<int:intern_id>', methods=['POST'])
def delete_profile(intern_id):
    intern = Intern.query.get_or_404(intern_id)
    db.session.delete(intern)
    db.session.commit()
    flash('Profile deleted successfully!', 'success')
    return redirect(url_for('view_interns'))

@app.route('/delete_organization/<int:organization_id>', methods=['POST'])
def delete_organization(organization_id):
    organization = Organization.query.get_or_404(organization_id)
    db.session.delete(organization)
    db.session.commit()
    flash('Organization deleted successfully!', 'success')
    return redirect(url_for('view_jobs'))

mail = Mail(app)

def send_email(recipient, subject, body):
    msg = Message(subject, recipients=[recipient])
    msg.body = body
    mail.send(msg)

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    if request.method == 'POST':
        from_email = request.form.get('from_email')
        to_email = request.form.get('to_email')
        subject = request.form.get('subject')
        message = request.form.get('message')

        msg = Message(subject, sender=from_email, recipients=[to_email])
        msg.body = message
        mail.send(msg)

        flash('Message sent successfully!', 'success')
        return redirect(url_for('view_interns'))
    else:
        flash('Invalid request!', 'error')
        return redirect(url_for('view_interns'))

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
        major = request.form['major']
        profile_photo = request.files.get('profile_photo')

        if not intern_email.endswith(f'{next_year_suffix}@bergen.org'):
            flash('Only 11th grade bergen tech students are allowed to register.', 'error')
            return redirect(url_for('register_intern'))

        if intern_password != intern_confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('register_intern'))

        hashed_password = generate_password_hash(intern_password)

        existing_intern = Intern.query.filter_by(intern_email=intern_email).first()
        if existing_intern:
            flash('An account with this email already exists. Please use a different email.', 'error')
            return redirect(url_for('register_intern'))

        profile_photo_filename = None
        if profile_photo and allowed_file(profile_photo.filename):
            profile_photo_filename = secure_filename(profile_photo.filename)
            profile_photo.save(os.path.join(app.config['UPLOAD_FOLDER'], profile_photo_filename))

        new_intern = Intern(
            intern_name=intern_name,
            intern_email=intern_email,
            graduation_year=graduation_year,
            intern_password=hashed_password,
            major=major,
            profile_photo=profile_photo_filename
        )
        db.session.add(new_intern)

        try:
            db.session.commit()
        except IntegrityError as e:
            db.session.rollback()
            flash('An error occurred while registering. Please try again.', 'error')
            return redirect(url_for('register_intern'))

        token = serializer.dumps(intern_email, salt='email-verification')
        verification_url = url_for('verify_email', token=token, _external=True)
        message = f'Click the following link to verify your email address: {verification_url}'
        send_email(intern_email, 'Email Verification', message)

        flash('A verification email has been sent to your email address. Please verify your email to complete registration. CHECK SPAM BOX!', 'success')
        return redirect(url_for('login'))

    return render_template('register_intern.html')

@app.route('/verify_email/<token>')
def verify_email(token):
    try:
        intern_email = serializer.loads(token, salt='email-verification')
        intern = Intern.query.filter_by(intern_email=intern_email).first()
        if intern:
            intern.email_verified = True
            db.session.commit()
            flash('Your email has been verified successfully!', 'success')
        else:
            flash('Invalid verification link.', 'error')
    except:
        flash('The verification link is invalid or has expired.', 'error')

    return redirect(url_for('login'))

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

        token = serializer.dumps(admin_email, salt='admin-registration')
        verification_url = url_for('verify_admin_registration', token=token, _external=True)
        message = f'Hello, {admin_email} has registered as an Admin to the InternLink website. ' \
                  f'Click the following link to complete the registration: {verification_url}\n\nBest Regards,\nInternLink'
        send_email('leolan25@bergen.org', 'Admin Registration Verification', message)

        flash('Admin registration pending. Email verification sent to Mrs. Buccino.', 'success')
        return redirect(url_for('login'))

    return render_template('register_admin.html')

@app.route('/verify_admin_registration/<token>', methods=['GET'])
def verify_admin_registration(token):
    try:
        admin_email = serializer.loads(token, salt='admin-registration')
        admin = Admin.query.filter_by(admin_email=admin_email).first()
        if admin:
            admin.registration_verified = True
            db.session.commit()
            flash('Admin registration verified successfully!', 'success')
        else:
            flash('Invalid verification link.', 'error')
    except:
        flash('The verification link is invalid or has expired.', 'error')

    return redirect(url_for('login'))

@app.route('/add_organization', methods=['GET', 'POST'])
@login_required
def add_organization():
    if current_user.is_authenticated and session['user_type'] == 'Admin':
        if request.method == 'POST':
            company_name = request.form['company_name']
            website = request.form['website']
            street_address = request.form['street_address']
            city = request.form['city']
            state = request.form['state']
            zip_code = request.form['zip_code']
            phone = request.form['phone']
            email = request.form['email']
            internship_mentor = request.form['internship_mentor']
            internship_topic = request.form['internship_topic']
            majors = request.form.getlist('selected_majors')
            major_string = ', '.join(majors)

            new_organization = Organization(
                company_name=company_name,
                website=website,
                street_address=street_address,
                city=city,
                state=state,
                zip_code=zip_code,
                phone=phone,
                email=email,
                internship_mentor=internship_mentor,
                internship_topic=internship_topic,
                major=major_string
            )

            db.session.add(new_organization)
            db.session.commit()

            flash('Organization added successfully!', 'success')
            return redirect(url_for('add_organization'))

        return render_template('add_organization.html')
    else:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('index'))

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
            if intern_user.email_verified:
                session['user_id'] = intern_user.id
                session['user_type'] = 'Intern'
                login_user(intern_user)
                flash('Logged in successfully!', 'success')
                return redirect(url_for('profile_intern'))
            else:
                flash('Please verify your email address to login.', 'error')
                return redirect(url_for('login'))

        admin_user = Admin.query.filter_by(admin_email=email).first()
        if admin_user and check_password_hash(admin_user.admin_password, password):
            if admin_user.registration_verified:
                session['user_id'] = admin_user.id
                session['user_type'] = 'Admin'
                login_user(admin_user)
                flash('Logged in successfully!', 'success')
                return redirect(url_for('profile_admin'))
            else:
                flash('The account has not been approved by the Admin yet. Please wait or contact Mrs. Buccino.', 'error')

        flash('Invalid email or password. Please try again.', 'error')
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route("/view_jobs", methods=['GET', 'POST'])
@login_required
def view_jobs():
    if request.method == 'POST':
        view_option = request.form.get('view_option', 'cards')
    else:
        view_option = request.args.get('view_option', 'cards')

    major_filter = request.args.get('major', '')

    if major_filter:
        organizations = Organization.query.filter(Organization.major.ilike(f'%{major_filter}%')).order_by(Organization.id.desc()).all()
    else:
        organizations = Organization.query.order_by(Organization.id.desc()).all()

    return render_template('view_jobs.html', organizations=organizations, view_option=view_option, major_filter=major_filter)

@app.before_request
def require_two_factor_auth():
    if request.path in ['/view_interns', '/add_organization']:
        if 'authenticated' not in session:
            return redirect(url_for('two_factor_auth'))

@app.route('/view_interns', methods=['GET', 'POST'])
@login_required
def view_interns():
    if current_user.is_authenticated and session['user_type'] == 'Admin':
        view_option = request.form.get('view_option', 'cards')
        interns = Intern.query.all()
        organization = Organization
        return render_template("view_interns.html", view_option=view_option, interns=interns, Organization=organization)
    else:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('index'))

@app.route("/two_factor_auth", methods=['GET', 'POST'])
def two_factor_auth():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == '12345':
            session['authenticated'] = True
            flash('Successfully two-factor authenticated!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Incorrect password. Please try again.', 'error')

    return render_template('two_factor_auth.html')

@app.route("/profile/intern")
def profile_intern():
    if session.get('user_id') and session.get('user_type') == 'Intern' and current_user.is_authenticated:
        user_id = session['user_id']
        intern = Intern.query.get(user_id)
        organization = Organization
        login_user(intern)
        return render_template("profile.html", user=intern, user_type='Intern', Organization=organization)
    else:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('index'))

@app.route("/profile/admin")
def profile_admin():
    if session.get('user_id') and session.get('user_type') == 'Admin' and current_user.is_authenticated:
        user_id = session['user_id']
        admin = Admin.query.get(user_id)
        login_user(admin)
        return render_template("profile.html", user=admin, user_type='Admin')
    else:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('index'))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/edit_profile', methods=['POST'])
def edit_profile():
    user_id = session['user_id']
    user_type = session.get('user_type')

    if user_type == 'Intern':
        user = Intern.query.get(user_id)
        user.intern_name = request.form.get('intern_name', user.intern_name)
        user.intern_email = request.form.get('intern_email', user.intern_email)
        user.graduation_year = request.form.get('graduation_year', user.graduation_year)
        user.profile_photo = user.profile_photo
        if 'resume' in request.files:
            resume_file = request.files['resume']
            if resume_file and allowed_file(resume_file.filename):
                filename = secure_filename(resume_file.filename)
                resume_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                user.resume = filename
    elif user_type == 'Admin':
        user = Admin.query.get(user_id)
        user.admin_name = request.form.get('admin_name', user.admin_name)
        user.admin_email = request.form.get('admin_email', user.admin_email)
        new_password = request.form.get('admin_password')
        if new_password:
            user.admin_password = generate_password_hash(new_password)
    db.session.commit()
    flash('Profile updated successfully!', 'success')
    return redirect(url_for(f'profile_{user_type.lower()}'))

@app.route('/remove_resume', methods=['POST'])
def remove_resume():
    user_id = request.form.get('user_id')
    user_type = session.get('user_type')

    if user_type == 'Intern':
        user = Intern.query.get(user_id)
        user.resume = None

    elif user_type == 'Admin':
        pass

    db.session.commit()
    flash('Resume removed successfully!', 'success')
    return redirect(url_for(f'profile_{user_type.lower()}'))

@app.route('/edit_interns/<int:intern_id>', methods=['GET', 'POST'])
def edit_interns(intern_id):
    intern = Intern.query.get(intern_id)
    if intern is None:
        flash('Intern not found.', 'error')
        return redirect(url_for('view_interns'))

    if request.method == 'POST':
        intern_name = request.form['intern_name']
        intern_email = request.form['intern_email']
        graduation_year = request.form['graduation_year']
        major = request.form['major']
        resume = request.files['resume']

        intern.intern_name = intern_name
        intern.intern_email = intern_email
        intern.graduation_year = graduation_year
        intern.major = major

        if resume:
            filename = secure_filename(resume.filename)
            resume.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            intern.resume = filename

        if 'delete_claimed_job' in request.form:
            intern.claimed_jobs.clear()

        db.session.commit()
        flash('Intern information updated successfully.', 'success')
        return redirect(url_for('view_interns'))

    return render_template('view_interns.html', intern=intern)

@app.route('/edit_profile_photo', methods=['POST'])
@login_required
def edit_profile_photo():
    if 'profile_photo' not in request.files:
        flash('No file part!', 'danger')
        return redirect(url_for('profile_intern'))

    file = request.files['profile_photo']

    if file.filename == '':
        flash('No selected file!', 'danger')
        return redirect(url_for('profile_intern'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        current_user.profile_photo = filename
        db.session.commit()
        flash('Profile photo updated successfully!', 'success')
    else:
        flash('Invalid file type!', 'danger')

    return redirect(url_for('profile_intern'))

@app.route('/download_resume/<filename>')
def download_resume(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == "__main__":
    app.run()
