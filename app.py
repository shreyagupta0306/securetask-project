import os
import hashlib
from sqlalchemy import text
from flask import Flask, jsonify, render_template, redirect, request, url_for, session
from flask_wtf.csrf import CSRFProtect
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import bcrypt
from models import db, User, Category, Task
from werkzeug.utils import secure_filename
from flask import send_from_directory
from flask_wtf import FlaskForm
from flask_talisman import Talisman

app = Flask(__name__)
app.config['WTF_CSRF_ENABLED'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-fallback-secret-key')
csrf = CSRFProtect(app)

Talisman(app, content_security_policy=None, force_https=False)

# Cookie Security Configurations
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Configurations
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///securetask.db'

AWS_SECRET_KEY = os.environ.get('AWS_SECRET_KEY', '')
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'default_dev_secret_key')
app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-fallback-secret-key')
csrf = CSRFProtect(app)

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

db.init_app(app)
jwt = JWTManager(app)

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# Updated /register to use bcrypt
@app.route('/register', methods=['POST'])
@csrf.exempt
def register():
    # ...
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Hash password using the imported bcrypt package
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Save user to DB
    new_user = User(username=username, password_hash=hashed_pw)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

# Updated /login to store session['user_id']
@app.route('/login', methods=['GET', 'POST'])
@csrf.exempt
def login():
    if request.method == 'GET':
        return render_template('login.html')

    # Handle form submission or JSON
    if request.is_json:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
    else:
        username = request.form.get('username')
        password = request.form.get('password')

    user = User.query.filter_by(username=username).first()

    if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
        # THIS IS THE CRITICAL LINE: Save user ID to session
        session['user_id'] = user.id
        
        if request.is_json:
            return jsonify({"message": "Login successful"}), 200
        return redirect('/dashboard')

    return render_template('login.html', error="Invalid credentials")

# Updated /logout route
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    search_query = request.args.get('q', '').strip()
    category_id = request.args.get('category', '').strip()

    try:
        # Base query restricted ONLY to the logged-in user
        query = Task.query.filter_by(user_id=user_id)

        # Apply search filter if provided
        if search_query:
            escaped_query = search_query.replace('%', r'\%').replace('_', r'\_')
            query = query.filter(Task.title.ilike(f"%{escaped_query}%"))

        # Apply category filter if provided
        if category_id:
            query = query.filter_by(category_id=category_id)

        tasks = query.all()
        categories = Category.query.all()

        return render_template(
            'dashboard.html',
            tasks=tasks,
            categories=categories,
            search=search_query
        )
    except Exception as e:
        return render_template('dashboard.html', tasks=[], categories=[], search='')

@app.route('/task/create', methods=['POST'])
def create_task():
    title = request.form.get('title')
    description = request.form.get('description')
    category_id = request.form.get('category_id')

    user_id = session.get('user_id', 1)

    new_task = Task(
        title=title,
        description=description,
        user_id=user_id,
        category_id=int(category_id) if category_id else None
    )
    db.session.add(new_task)
    db.session.commit()

    return redirect(url_for('dashboard'))

@app.route('/task/update/<int:task_id>', methods=['POST'])
def update_task(task_id):
    user_id = session.get('user_id')
    
    if not user_id:
        try:
            from flask_jwt_extended import verify_jwt_in_request
            verify_jwt_in_request()
            current_user_identity = get_jwt_identity()
            user = User.query.filter_by(username=current_user_identity).first()
            if user:
                user_id = user.id
        except Exception:
            pass

    if not user_id:
        return jsonify({"message": "Unauthorized"}), 401

    task = Task.query.filter_by(id=task_id, user_id=user_id).first_or_404()
    task.title = request.form.get('title', task.title)
    task.description = request.form.get('description', task.description)
    task.status = request.form.get('status', task.status)
    
    category_id = request.form.get('category_id')
    if category_id:
        task.category_id = int(category_id)
    
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/task/delete/<int:task_id>', methods=['POST'])
def delete_task(task_id):
    user_id = session.get('user_id')
    
    if not user_id:
        try:
            from flask_jwt_extended import verify_jwt_in_request
            verify_jwt_in_request()
            current_user_identity = get_jwt_identity()
            user = User.query.filter_by(username=current_user_identity).first()
            if user:
                user_id = user.id
        except Exception:
            pass

    if not user_id:
        return jsonify({"message": "Unauthorized"}), 401

    task = Task.query.filter_by(id=task_id, user_id=user_id).first_or_404()
    db.session.delete(task)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)

    if request.method == 'POST':
        user.username = request.form.get('username')
        db.session.commit()
        return redirect(url_for('profile'))

    return render_template('profile.html', user=user)

@app.route('/api/docs', methods=['GET'])
def api_docs():
    docs = {
        "version": "1.0",
        "endpoints": {
            "POST /register": "Register a new user",
            "POST /login": "Authenticate user and receive JWT",
            "POST /task/create": "Create a new task",
            "GET /dashboard": "View tasks, supports query parameters ?q=search & ?category=id",
            "POST /task/update/<id>": "Update specific task attributes",
            "POST /task/delete/<id>": "Delete a specific task",
            "GET /profile": "Retrieve and update user profile details"
        }
    }
    return jsonify(docs), 200

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'txt'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        return jsonify({"message": f"File uploaded successfully as {filename}"}), 200

    return jsonify({"error": "File type not allowed"}), 400

@app.route('/view-file', methods=['GET'])
def view_file():
    filename = request.args.get('file', '')
    if not filename:
        return jsonify({"error": "Filename required"}), 400
        
    safe_name = secure_filename(filename)
    try:
        return send_from_directory(UPLOAD_FOLDER, safe_name)
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Server'] = 'SecureServer'
    return response

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Auto-create default_user if it doesn't exist yet
        if not User.query.filter_by(username='default_user').first():
            salt = bcrypt.gensalt()
            valid_hash = bcrypt.hashpw('password123'.encode('utf-8'), salt).decode('utf-8')
            db.session.add(User(username='default_user', password_hash=valid_hash))
            db.session.commit()
            print("Successfully seeded default_user into database!")
            
    app.run(debug=True)