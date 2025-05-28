import os
import pyotp # For MFA
import qrcode # For MFA QR code
import io # For MFA QR code image in memory
from flask import Flask, render_template, redirect, url_for, flash, request, session, send_from_directory, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet # For encryption
from functools import wraps # For RBAC decorator

from models import db, User, File
from forms import RegistrationForm, LoginForm, FileUploadForm, MFASetupForm

# Configuration
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'user_uploads_encrypted') # Store encrypted files here
ENCRYPTION_KEY_FILE = os.path.join(BASE_DIR, 'secret.key')

# --- Encryption Key Management ---
def generate_key():
    """Generates a new Fernet key and saves it to a file."""
    key = Fernet.generate_key()
    with open(ENCRYPTION_KEY_FILE, "wb") as key_file:
        key_file.write(key)
    return key

def load_key():
    """Loads the Fernet key from the key file. Generates one if not found."""
    if not os.path.exists(ENCRYPTION_KEY_FILE):
        return generate_key()
    with open(ENCRYPTION_KEY_FILE, "rb") as key_file:
        return key_file.read()

ENCRYPTION_KEY = load_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

# --- Application Setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24) # Strong secret key for session management
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'instance', 'site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Initialize extensions
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' # Redirect to 'login' view if @login_required
login_manager.login_message_category = 'info'

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
if not os.path.exists(os.path.join(BASE_DIR, 'instance')):
    os.makedirs(os.path.join(BASE_DIR, 'instance'))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- RBAC Decorator ---
def role_required(role_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role_name:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ... (previous app.py content) ...

def encrypt_file(file_data):
    return cipher_suite.encrypt(file_data)

def decrypt_file(encrypted_data):
    return cipher_suite.decrypt(encrypted_data)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    form = FileUploadForm()
    if form.validate_on_submit():
        file = form.file.data
        filename = secure_filename(file.filename)
        
        # Read file content
        file_content = file.read()
        
        # Encrypt file content
        encrypted_content = encrypt_file(file_content)
        
        # Create a unique path for the encrypted file
        # For simplicity, using user_id and filename, could be more robust (e.g., UUID)
        user_upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))
        if not os.path.exists(user_upload_dir):
            os.makedirs(user_upload_dir)
        
        encrypted_filename = f"{filename}.enc" # Append .enc to signify encrypted
        encrypted_filepath = os.path.join(user_upload_dir, encrypted_filename)
        
        with open(encrypted_filepath, 'wb') as ef:
            ef.write(encrypted_content)
            
        new_file = File(filename=filename, filepath_encrypted=encrypted_filepath, user_id=current_user.id)
        db.session.add(new_file)
        db.session.commit()
        flash(f'File "{filename}" uploaded and encrypted successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('upload_file.html', title='Upload File', form=form)

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file_record = File.query.get_or_404(file_id)
    
    # RBAC: Check if user owns the file or is an admin
    if file_record.user_id != current_user.id and current_user.role != 'admin':
        flash('You do not have permission to download this file.', 'danger')
        return redirect(url_for('index'))

    try:
        with open(file_record.filepath_encrypted, 'rb') as ef:
            encrypted_content = ef.read()
        
        decrypted_content = decrypt_file(encrypted_content)
        
        return send_file(
            io.BytesIO(decrypted_content),
            mimetype='application/octet-stream', # Generic binary type
            as_attachment=True,
            download_name=file_record.filename # Original filename
        )
    except Exception as e:
        app.logger.error(f"Error downloading/decrypting file {file_id}: {e}")
        flash('Error downloading file. It might be corrupted or the key is incorrect.', 'danger')
        return redirect(url_for('index'))
# ... (previous imports) ...
# import pyotp, qrcode, io (already there)

@app.route('/setup_mfa', methods=['GET', 'POST'])
@login_required
def setup_mfa():
    form = MFASetupForm()
    if current_user.mfa_enabled:
        flash('MFA is already enabled for your account.', 'info')
        return redirect(url_for('index'))

    if 'mfa_secret_pending' not in session:
        # Generate a new secret for this setup attempt
        session['mfa_secret_pending'] = pyotp.random_base32()
    
    secret = session['mfa_secret_pending']
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=current_user.email, issuer_name="SecureShareApp")
    
    # Generate QR code
    img = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    qr_code_data = buf.getvalue()

    import base64
    qr_code_b64 = base64.b64encode(qr_code_data).decode('utf-8')


    if form.validate_on_submit():
        if totp.verify(form.token.data):
            current_user.mfa_secret = secret
            current_user.mfa_enabled = True
            db.session.commit()
            session.pop('mfa_secret_pending', None) # Clear pending secret
            flash('MFA has been successfully enabled!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid verification code. Please try again.', 'danger')
            
    return render_template('setup_mfa.html', title='Setup MFA', form=form, qr_code=qr_code_b64, mfa_secret_display=secret)


@app.route('/verify_mfa_login', methods=['GET', 'POST'])
def verify_mfa_login():
    if 'user_id_for_mfa' not in session:
        flash('MFA verification process not initiated.', 'warning')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id_for_mfa'])
    if not user or not user.mfa_enabled:
        flash('MFA not required or user not found.', 'warning')
        session.pop('user_id_for_mfa', None)
        session.pop('remember_me_for_mfa', None)
        return redirect(url_for('login'))

    form = MFASetupForm() # Re-use for token input, or create a simpler one
    if form.validate_on_submit(): # Using token field from MFASetupForm
        totp = pyotp.TOTP(user.mfa_secret)
        if totp.verify(form.token.data):
            remember_me = session.get('remember_me_for_mfa', False)
            login_user(user, remember=remember_me)
            session.pop('user_id_for_mfa', None)
            session.pop('remember_me_for_mfa', None)
            flash('MFA verified. Login successful!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Invalid MFA token.', 'danger')
    return render_template('verify_mfa_login.html', title='Verify MFA', form=form)
# ...
from datetime import datetime

@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}
# ... (your existing imports and setup) ...

@app.route('/admin')
@login_required
@role_required('admin') # Protect this route
def admin_dashboard():
    users = User.query.all()
    all_files = File.query.all()

    # --- Add this code to create the user_map ---
    # Create a dictionary mapping user ID to their username
    # This assumes your User model has 'id' and 'username' attributes
    user_map = {user.id: user.username for user in users}
    # If you preferred the email: user_map = {user.id: user.email for user in users}
    # If you wanted the whole user object (less common for just display): user_map = {user.id: user for user in users}
    # --------------------------------------------

    # --- Add user_map=user_map to the render_template call ---
    return render_template('admin_dashboard.html',
                           title='Admin Dashboard',
                           users=users,       # Pass the list of users (used for the User list part)
                           files=all_files,   # Pass the list of files
                           user_map=user_map) # <<< Pass the user_map dictionary
    # ----------------------------------------------------------

# ... (rest of your app.py code) ...

@app.route('/disable_mfa', methods=['POST']) # Use POST for actions that change state
@login_required
def disable_mfa():
    if current_user.mfa_enabled:
        # For critical actions, consider asking for password confirmation
        current_user.mfa_enabled = False
        current_user.mfa_secret = None
        db.session.commit()
        flash('MFA has been disabled.', 'success')
    else:
        flash('MFA is not currently enabled.', 'info')
    return redirect(url_for('index')) # Or a profile page

# ... (rest of app.py)
@app.route('/delete/<int:file_id>', methods=['GET']) # Should be POST for safety, but GET for demo simplicity
@login_required
def delete_file(file_id):
    file_record = File.query.get_or_404(file_id)
    if file_record.user_id != current_user.id and current_user.role != 'admin':
        flash('You do not have permission to delete this file.', 'danger')
        abort(403)
    
    try:
        if os.path.exists(file_record.filepath_encrypted):
            os.remove(file_record.filepath_encrypted)
        db.session.delete(file_record)
        db.session.commit()
        flash(f'File "{file_record.filename}" deleted successfully.', 'success')
    except Exception as e:
        app.logger.error(f"Error deleting file {file_id}: {e}")
        db.session.rollback()
        flash('Error deleting file.', 'danger')
    return redirect(url_for('index'))

# ... (rest of app.py)
# --- Routes ---
@app.route('/')
@app.route('/index')
@login_required
def index():
    # RBAC in action: Admins see all files, users see their own
    if current_user.role == 'admin':
        files = File.query.all()
    else:
        files = File.query.filter_by(user_id=current_user.id).all()
    
    # For simplicity, create a default admin if none exists on first run
    # In production, you'd have a separate script or process for this
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin', email='admin@example.com', role='admin')
        admin_user.set_password('ChangeMe!') # IMPORTANT: Change this password
        db.session.add(admin_user)
        db.session.commit()
        flash('Default admin account created. Username: admin, Password: ChangeMe! Please change it immediately.', 'warning')

    return render_template('index.html', title='Dashboard', files=files, User=User)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        # For demo, first registered user is admin (can be changed)
        if User.query.count() == 0:
            user.role = 'admin'
            flash('First user registered as admin.', 'info')
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter((User.username == form.username_or_email.data) | (User.email == form.username_or_email.data)).first()
        if user and user.check_password(form.password.data):
            if user.mfa_enabled:
                # Store user_id in session to retrieve after MFA
                session['user_id_for_mfa'] = user.id
                session['remember_me_for_mfa'] = form.remember.data
                return redirect(url_for('verify_mfa_login'))
            else:
                login_user(user, remember=form.remember.data)
                flash('Login successful!', 'success')
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check username/email and password.', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('user_id_for_mfa', None) # Clear MFA session data
    session.pop('remember_me_for_mfa', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# --- Database Creation Context ---
with app.app_context():
    db.create_all() # Creates tables if they don't exist

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=False)
