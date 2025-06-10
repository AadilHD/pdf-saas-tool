from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    current_user,
    logout_user,
)
from datetime import datetime
import os
from PyPDF2 import PdfReader, PdfWriter
import re
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash

def admin_required(view_func):
    from functools import wraps
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Admins only.")
            return redirect(url_for("index"))
        return view_func(*args, **kwargs)
    return wrapped_view

app = Flask(__name__, static_folder='static')
app.secret_key = 'your_secret_key_here'  # Replace with a secure key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    merge_count = db.Column(db.Integer, default=0)
    last_reset = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def index():
    return render_template('index.html', current_user=current_user)

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/merge-selected', methods=['POST'])
@login_required
def merge_selected_pages():
    # Monthly reset
    today = datetime.utcnow()
    if current_user.last_reset is None or current_user.last_reset.month != today.month:
        current_user.merge_count = 0
        current_user.last_reset = today
        db.session.commit()

    # Enforce free user limit
    if current_user.merge_count >= 5:
        flash("❌ Monthly merge limit reached. Please upgrade to continue.")
        return redirect(url_for("index"))

    files = request.files.getlist('pdfs')
    page_ranges = request.form.getlist('ranges')

    if len(files) != len(page_ranges):
        return "Number of files and ranges must match.", 400

    writer = PdfWriter()

    for file, range_str in zip(files, page_ranges):
        start_str, end_str = range_str.split('-')
        start = int(start_str) - 1
        end = int(end_str)

        reader = PdfReader(file)
        for i in range(start, min(end, len(reader.pages))):
            writer.add_page(reader.pages[i])

    output_path = os.path.join(UPLOAD_FOLDER, "custom_merge.pdf")
    with open(output_path, "wb") as f:
        writer.write(f)

    # Count this merge
    current_user.merge_count += 1
    db.session.commit()

    return send_file(output_path, as_attachment=True)

@app.route('/get-merge-count')
@login_required
def get_merge_count():
    return {'count': current_user.merge_count}

@app.route('/delete-account', methods=['POST'])
@login_required
def delete_account():
    """Delete the currently authenticated user's account."""
    user = current_user

    if user:
        db.session.delete(user)
        db.session.commit()
        logout_user()
        flash("Your account has been deleted.")

    return redirect(url_for("signup"))

@app.route('/delete-user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash("User deleted.")
    return redirect(url_for('admin_dashboard'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # ✅ Validate email format
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            flash('Invalid email format.')
            return redirect(url_for('signup'))

        # ✅ Validate password strength
        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', password):
            flash('Password must be at least 8 characters long and include a capital letter, number, and special character.')
            return redirect(url_for('signup'))
        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            flash("❌ Email already registered.")
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password)
        new_user = User(email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        flash("✅ Signup successful!")
        return redirect(url_for('index'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash("✅ Login successful!")
            return redirect(url_for('index'))
        else:
            flash("❌ Invalid email or password.")

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("👋 You’ve been logged out.")
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
