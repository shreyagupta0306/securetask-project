from flask import Flask, jsonify, request, render_template, redirect, url_for
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import bcrypt
from models import db, User, Category, Task

app = Flask(__name__)

# Configurations
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///securetask.db'
app.config['JWT_SECRET_KEY'] = 'your-super-secret-key-change-this'

db.init_app(app)
jwt = JWTManager(app)
with app.app_context():
    db.create_all()

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

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    new_user = User(username=username, password_hash=hashed_password)
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
@jwt_required()
def dashboard():
    current_user_identity = get_jwt_identity()
    user = User.query.filter_by(username=current_user_identity).first()
    if not user:
        return jsonify({"message": "User not found"}), 404
        
    search_query = request.args.get('q', '')
    category_id = request.args.get('category', '')
    
    query = Task.query.filter_by(user_id=user.id)
    
    if search_query:
        query = query.filter(Task.title.ilike(f'%{search_query}%'))
    if category_id:
        query = query.filter_by(category_id=category_id)
        
    tasks = query.all()
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
@jwt_required()
def profile():
    current_user_identity = get_jwt_identity()
    user = User.query.filter_by(username=current_user_identity).first_or_404()
    
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
            "POST /task/create": "Create a new task (Requires JWT)",
            "GET /dashboard": "View tasks, supports query parameters ?q=search & ?category=id",
            "POST /task/update/<id>": "Update specific task attributes",
            "POST /task/delete/<id>": "Delete a specific task",
            "GET /profile": "Retrieve and update user profile details"
        }
    }
    return jsonify(docs), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)