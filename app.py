import os
import hashlib
from sqlalchemy import text
from flask import Flask, jsonify, render_template, redirect, request, url_for
from flask_wtf.csrf import CSRFProtect
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import bcrypt
from models import db, User, Category, Task
from werkzeug.utils import secure_filename
from flask import send_from_directory
from flask_wtf import FlaskForm

app = Flask(__name__)
app = Flask(__name__)

# Cookie Security Configurations
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True only in HTTPS production
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Configurations
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///securetask.db'

# VULNERABILITY: Hardcoded Secrets (For Gitleaks / Semgrep)
# SECURE: Retrieve secrets from environment variables (No hardcoded strings)
AWS_SECRET_KEY = os.environ.get('AWS_SECRET_KEY', '')
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'default_dev_secret_key')
app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
# Enable CSRF Protection
app.config['SECRET_KEY'] = os.environ.get(
    'SECRET_KEY', 'your-fallback-secret-key'
)
csrf = CSRFProtect(app)

# Upload folder setup
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

db.init_app(app)
jwt = JWTManager(app)
@app.route('/')
def home():
    return redirect(url_for('dashboard'))
# Route: User Registration
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Username and password required"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"message": "User already exists"}), 400

    # VULNERABILITY: Weak hashing algorithm (MD5 instead of bcrypt)
    weak_password_hash = hashlib.md5(password.encode('utf-8')).hexdigest()

    new_user = User(username=username, password_hash=weak_password_hash)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully"}), 201

# Route: User Login & JWT Generation
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    
    if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
        
    return jsonify({"message": "Invalid credentials"}), 401

# Week 2 Routes: Dashboard, Task CRUD, Profile & API Docs
@app.route('/dashboard', methods=['GET'])
# VULNERABILITY: Authentication Bypass (JWT guard intentionally removed)
@app.route('/dashboard', methods=['GET'])
def dashboard():
    search_query = request.args.get('q', '').strip()
    category_id = request.args.get('category', '').strip()
    
    try:
        if search_query:
            # Escape literal SQL wildcard characters (%) and (_)
            escaped_query = search_query.replace('%', r'\%').replace('_', r'\_')
            tasks = Task.query.filter(Task.title.ilike(f"%{escaped_query}%")).all()
        else:
            tasks = Task.query.all()

        categories = Category.query.all()
        return render_template(
            'dashboard.html', 
            tasks=tasks, 
            categories=categories, 
            search=search_query
        )
    except Exception as e:
        # Avoid breaking on invalid queries or database errors
        return render_template('dashboard.html', tasks=[], categories=[], search='')
@app.route('/task/create', methods=['POST'])
@jwt_required()
def create_task():
    current_user_identity = get_jwt_identity()
    user = User.query.filter_by(username=current_user_identity).first()
    
    title = request.form.get('title')
    description = request.form.get('description')
    category_id = request.form.get('category_id')
    
    new_task = Task(
        title=title, 
        description=description, 
        user_id=user.id, 
        category_id=category_id if category_id else None
    )
    db.session.add(new_task)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/task/update/<int:task_id>', methods=['POST'])
@jwt_required()
def update_task(task_id):
    current_user_identity = get_jwt_identity()
    user = User.query.filter_by(username=current_user_identity).first()
    
    task = Task.query.filter_by(id=task_id, user_id=user.id).first_or_404()
    task.title = request.form.get('title')
    task.description = request.form.get('description')
    task.status = request.form.get('status', task.status)
    task.category_id = request.form.get('category_id')
    
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/task/delete/<int:task_id>', methods=['POST'])
@jwt_required()
def delete_task(task_id):
    current_user_identity = get_jwt_identity()
    user = User.query.filter_by(username=current_user_identity).first()
    
    task = Task.query.filter_by(id=task_id, user_id=user.id).first_or_404()
    db.session.delete(task)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/profile', methods=['GET', 'POST'])
# VULNERABILITY: Missing authentication check (Auth Bypass / IDOR)
def profile():
    user_id = request.args.get('user_id', 1)
    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404
        
    if request.method == 'POST':
        user.username = request.form.get('username')
        db.session.commit()
        return redirect(url_for('profile', user_id=user.id))
        
    return render_template('profile.html', user=user)

@app.route('/api/docs', methods=['GET'])
def api_docs():
    docs = {
        "version": "1.0",
        "endpoints": {
            "POST /register": "Register a new user",
            "POST /login": "Authenticate user and receive JWT",
            "POST /task/create": "Create a new task (Requires JWT)",
            "GET /dashboard": "View tasks, supports query parameters ?q=search & ?category=id",
            "POST /task/update/<id>": "Update specific task attributes",
            "POST /task/delete/<id>": "Delete a specific task",
            "GET /profile": "Retrieve and update user profile details"
        }
    }
    return jsonify(docs), 200
# VULNERABILITY: Insecure File Upload & Path Traversal
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'txt'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# SECURE: File Upload with Sanitized Filenames
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if file and allowed_file(file.filename):
        # SECURE: Strips directory traversal sequences like '../../'
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        return jsonify({"message": f"File uploaded successfully as {filename}"}), 200

    return jsonify({"error": "File type not allowed"}), 400

# SECURE: Safe File Viewing via send_from_directory (Prevents Path Traversal)
@app.route('/view-file', methods=['GET'])
def view_file():
    filename = request.args.get('file', '')
    if not filename:
        return jsonify({"error": "Filename required"}), 400
        
    # SECURE: secure_filename sanitizes inputs and send_from_directory prevents accessing parent directories
    safe_name = secure_filename(filename)
    try:
        return send_from_directory(UPLOAD_FOLDER, safe_name)
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        return f"<pre>{content}</pre>"
    except Exception as e:
        return jsonify({"verbose_error": str(e), "target_path": file_path}), 500
    # SECURE: Add HTTP Security Response Headers
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none';"
    )
    
    # Overwrite Server response header
    response.headers['Server'] = 'SecureServer'
    return response
if __name__ == '__main__':
    from werkzeug.serving import WSGIRequestHandler
    WSGIRequestHandler.server_version = "SecureServer"
    WSGIRequestHandler.sys_version = ""
    app.run(debug=True)