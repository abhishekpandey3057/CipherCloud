from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
import os, random, string
from werkzeug.utils import secure_filename
from datetime import datetime
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
from utils import encryption, aws_helpers

app = Flask(__name__)
app.secret_key = os.urandom(24)
bcrypt = Bcrypt(app)

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'Enter Your E-mail here' # John@gmail.com
app.config['MAIL_PASSWORD'] = 'Enter generated Password Here' #aaaa bbbb cccc dddd
mail = Mail(app)

# Upload settings
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'docx'}
MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB

# In-memory stores
users = {}         # {email: {password_hash, verified, role}}
pending_otps = {}  # {email: {otp, password_hash, role}}

# Helpers
def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')

        if email in users:
            flash("Email already registered. Please log in.")
            return redirect(url_for('login'))

        pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        otp = generate_otp()
        pending_otps[email] = {'otp': otp, 'password_hash': pw_hash, 'role': role}

        msg = Message("Your Signup OTP", sender="your-email@example.com", recipients=[email])
        msg.body = f"Your OTP for signing up is: {otp}"
        mail.send(msg)

        session['pending_email'] = email
        flash("OTP sent to your email. Please verify.")
        return redirect(url_for('verify_otp'))

    return render_template('signup.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    pending_email = session.get('pending_email')
    if not pending_email or pending_email not in pending_otps:
        flash("No pending signup found. Please signup.")
        return redirect(url_for('signup'))

    if request.method == 'POST':
        otp_entered = request.form.get('otp')
        if otp_entered == pending_otps[pending_email]['otp']:
            users[pending_email] = {
                'password_hash': pending_otps[pending_email]['password_hash'],
                'verified': True,
                'role': pending_otps[pending_email]['role']
            }
            pending_otps.pop(pending_email)
            session.pop('pending_email')
            flash("Signup successful! Please log in.")
            return redirect(url_for('login'))
        else:
            flash("Invalid OTP. Please try again.")

    return render_template('verify_otp.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = users.get(email)

        if user and user.get('verified') and bcrypt.check_password_hash(user['password_hash'], password):
            session['user'] = email
            flash("Login successful!")
            return redirect(url_for('sender_dashboard') if user['role'] == 'sender' else 'recipient_dashboard')
        else:
            flash("Invalid credentials or unverified account.")

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("Logged out successfully!")
    return redirect(url_for('index'))

@app.route('/sender/dashboard', methods=['GET', 'POST'])
def sender_dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)

        file = request.files['file']
        recipient_email = request.form.get('recipient_email')

        if file.filename == '' or not recipient_email:
            flash('No selected file or recipient email')
            return redirect(request.url)

        if not allowed_file(file.filename):
            flash('File type not allowed')
            return redirect(request.url)

        try:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            aes_key = encryption.generate_aes_key()
            encrypted_file_path = file_path + ".enc"
            encryption.encrypt_file_aes(file_path, encrypted_file_path, aes_key)

            recipient_public_key = encryption.load_rsa_public_key("keys/recipient_public.pem")
            encrypted_aes_key = encryption.encrypt_key_rsa(aes_key, recipient_public_key)

            s3_url = aws_helpers.upload_file_to_s3(encrypted_file_path, filename + ".enc")
            metadata = {
                'file_id': filename,
                'owner': session['user'],
                'recipient': recipient_email,
                'encrypted_aes_key': encrypted_aes_key.hex(),
                'timestamp': datetime.utcnow().isoformat(),
                's3_url': s3_url
            }

            aws_helpers.store_metadata(metadata)
            flash('File uploaded and encrypted successfully!')
        except Exception as e:
            flash(f"Upload failed: {str(e)}")

        return redirect(url_for('sender_dashboard'))

    return render_template('sender_dashboard.html')

@app.route('/recipient/dashboard')
def recipient_dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    recipient_email = session['user']
    files = aws_helpers.get_files_for_recipient(recipient_email)
    return render_template('recipient_dashboard.html', files=files)

@app.route('/download/<file_id>', methods=['GET', 'POST'])
def download(file_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'private_key' not in request.files:
            flash('Private key file required')
            return redirect(request.url)

        private_key_file = request.files['private_key']
        passphrase = request.form.get('passphrase')

        try:
            metadata = aws_helpers.get_metadata(file_id)
            if not metadata:
                flash("File not found")
                return redirect(url_for('recipient_dashboard'))

            local_enc_path = os.path.join(app.config['UPLOAD_FOLDER'], file_id + ".enc")
            aws_helpers.download_file_from_s3(file_id + ".enc", local_enc_path)

            private_key_path = os.path.join(app.config['UPLOAD_FOLDER'], "temp_key.pem")
            private_key_file.save(private_key_path)

            recipient_private_key = encryption.load_rsa_private_key(private_key_path, passphrase.encode())
            encrypted_aes_key = bytes.fromhex(metadata['encrypted_aes_key'])
            aes_key = encryption.decrypt_key_rsa(encrypted_aes_key, recipient_private_key)

            decrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], "decrypted_" + file_id)
            encryption.decrypt_file_aes(local_enc_path, decrypted_file_path, aes_key)

            flash("File decrypted successfully!")
            return send_file(decrypted_file_path, as_attachment=True)
        except Exception as e:
            flash(f"Decryption failed: {str(e)}")
            return redirect(url_for('recipient_dashboard'))

    return render_template('recipient_dashboard.html', files=[file_id])

# Optional: Redirect short aliases to correct routes
@app.route('/recipient_dashboard')
def redirect_recipient_dashboard():
    return redirect(url_for('recipient_dashboard'))

@app.route('/sender_dashboard')
def redirect_sender_dashboard():
    return redirect(url_for('sender_dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
