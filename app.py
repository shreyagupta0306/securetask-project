import os
import hashlib
from sqlalchemy import text
from flask import Flask, jsonify, request, render_template, redirect, url_for
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import bcrypt
from models import db, User, Category, Task

app = Flask(__name__)

# Configurations
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///securetask.db'

# VULNERABILITY: Hardcoded Secrets (For Gitleaks / Semgrep)
AWS_SECRET_KEY = "AKIAIOSFODNN7ABCD1234567890SECKEY"
JWT_SECRET_KEY = "hardcoded_super_insecure_secret_12345"
app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY

# Upload folder setup
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

db.init_app(app)
jwt = JWTManager(app)
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
def dashboard():
    search_query = request.args.get('q', '')
    category_id = request.args.get('category', '')
    raw_sql = ""
    
    try:
        # VULNERABILITY: SQL Injection via direct string formatting
        if search_query:
            raw_sql = f"SELECT * FROM task WHERE title LIKE '%{search_query}%'"
            result = db.session.execute(text(raw_sql))
            tasks = result.fetchall()
        else:
            tasks = Task.query.all()
    except Exception as e:
        # VULNERABILITY: Verbose error handling (stack trace / query exposure)
        return jsonify({"database_error": str(e), "failed_query": raw_sql}), 500

    categories = Category.query.all()
    return render_template('dashboard.html', tasks=tasks, categories=categories, search=search_query)

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
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    # Saves with unvalidated name directly in the folder
    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)
    
    return jsonify({"message": f"File uploaded to {filepath}"}), 200

# VULNERABILITY: Directory Traversal to read arbitrary files
@app.route('/view-file', methods=['GET'])
def view_file():
    filename = request.args.get('file', '')
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        return f"<pre>{content}</pre>"
    except Exception as e:
        return jsonify({"verbose_error": str(e), "target_path": file_path}), 500
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)