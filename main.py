import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///petroleum_notes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads/notes'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'doc', 'docx', 'txt', 'ppt', 'pptx', 'zip', 'rar'}

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize database
db = SQLAlchemy(app)

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    filename = db.Column(db.String(300), nullable=False)
    original_filename = db.Column(db.String(300), nullable=False)
    file_size = db.Column(db.Integer)  # Size in bytes
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    downloads = db.Column(db.Integer, default=0)
    subject = db.relationship('Subject', backref=db.backref('notes', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def format_file_size(size_in_bytes):
    """Convert bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_in_bytes < 1024.0:
            return f"{size_in_bytes:.1f} {unit}"
        size_in_bytes /= 1024.0
    return f"{size_in_bytes:.1f} TB"

def init_database():
    """Initialize database with default data"""
    with app.app_context():
        db.create_all()
        
        # Create admin user if not exists
        if not User.query.filter_by(username='petroscholar').first():
            admin = User(
                username='petroscholar',
                password_hash=generate_password_hash('admin@123'),
                is_admin=True
            )
            db.session.add(admin)
            print("✓ Admin user created")
            print("  Username: admin")
            print("  Password: admin123")
            print("  Please change these credentials after first login!")
        
        # Create default subjects
        subjects_data = [
            ('Reservoir Engineering', 'Study of petroleum reservoirs and their behavior'),
            ('Drilling Engineering', 'Drilling operations, equipment, and technology'),
            ('Production Engineering', 'Oil and gas production methods and optimization'),
            ('Petroleum Geology', 'Geological aspects of petroleum exploration'),
            ('Well Logging', 'Formation evaluation and well logging techniques'),
            ('Petrophysics', 'Rock and fluid properties analysis'),
            ('Enhanced Oil Recovery', 'EOR methods and reservoir stimulation'),
            ('Well Testing', 'Reservoir characterization through testing'),
            ('Offshore Engineering', 'Offshore drilling and production systems'),
            ('Pipeline Engineering', 'Oil and gas transportation systems')
        ]
        
        for name, desc in subjects_data:
            if not Subject.query.filter_by(name=name).first():
                subject = Subject(name=name, description=desc)
                db.session.add(subject)
        
        db.session.commit()
        print("✓ Database initialized successfully")

# Routes
@app.route('/')
def index():
    subjects = Subject.query.all()
    recent_notes = Note.query.order_by(Note.upload_date.desc()).limit(6).all()
    total_notes = Note.query.count()
    total_subjects = Subject.query.count()
    
    # Format file sizes for display
    for note in recent_notes:
        note.formatted_size = format_file_size(note.file_size) if note.file_size else "Unknown"
    
    return render_template('index.html', 
                         subjects=subjects, 
                         recent_notes=recent_notes,
                         total_notes=total_notes,
                         total_subjects=total_subjects)

@app.route('/notes')
def notes():
    subject_id = request.args.get('subject_id', type=int)
    search_query = request.args.get('search', '')
    
    query = Note.query.join(Subject)
    
    if subject_id:
        query = query.filter(Note.subject_id == subject_id)
    
    if search_query:
        query = query.filter(
            (Note.title.ilike(f'%{search_query}%')) | 
            (Note.description.ilike(f'%{search_query}%'))
        )
    
    notes_list = query.order_by(Note.upload_date.desc()).all()
    subjects = Subject.query.all()
    
    # Format file sizes
    for note in notes_list:
        note.formatted_size = format_file_size(note.file_size) if note.file_size else "Unknown"
    
    return render_template('notes.html', 
                         notes=notes_list, 
                         subjects=subjects,
                         selected_subject=subject_id,
                         search_query=search_query)

@app.route('/download/<int:note_id>')
def download_note(note_id):
    note = Note.query.get_or_404(note_id)
    
    # Increment download count
    note.downloads += 1
    db.session.commit()
    
    try:
        return send_from_directory(
            app.config['UPLOAD_FOLDER'],
            note.filename,
            as_attachment=True,
            download_name=note.original_filename
        )
    except FileNotFoundError:
        abort(404)

@app.route('/about')
def about():
    total_notes = Note.query.count()
    total_subjects = Subject.query.count()
    total_downloads = db.session.query(db.func.sum(Note.downloads)).scalar() or 0
    return render_template('about.html', 
                         total_notes=total_notes,
                         total_subjects=total_subjects,
                         total_downloads=total_downloads)

@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy.html')

# Admin Routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_panel'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('admin_panel'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('admin_login.html')

@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    flash('Logged out successfully', 'info')
    return redirect(url_for('index'))

@app.route('/admin/panel')
@login_required
def admin_panel():
    total_notes = Note.query.count()
    total_subjects = Subject.query.count()
    recent_uploads = Note.query.order_by(Note.upload_date.desc()).limit(5).all()
    total_downloads = db.session.query(db.func.sum(Note.downloads)).scalar() or 0
    
    return render_template('admin_panel.html',
                         total_notes=total_notes,
                         total_subjects=total_subjects,
                         total_downloads=total_downloads,
                         recent_uploads=recent_uploads)

@app.route('/admin/upload', methods=['GET', 'POST'])
@login_required
def upload_notes():
    subjects = Subject.query.all()
    
    if request.method == 'POST':
        # Check if all fields are provided
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        title = request.form.get('title')
        description = request.form.get('description')
        subject_id = request.form.get('subject_id')
        
        if not title or not subject_id:
            flash('Title and Subject are required', 'error')
            return redirect(request.url)
        
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            # Secure the filename
            original_filename = secure_filename(file.filename)
            filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{original_filename}"
            
            # Save file
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            # Get file size
            file_size = os.path.getsize(file_path)
            
            # Create note record
            note = Note(
                subject_id=subject_id,
                title=title,
                description=description,
                filename=filename,
                original_filename=original_filename,
                file_size=file_size
            )
            
            db.session.add(note)
            db.session.commit()
            
            flash('Notes uploaded successfully!', 'success')
            return redirect(url_for('admin_panel'))
        else:
            flash('File type not allowed', 'error')
    
    return render_template('upload_notes.html', subjects=subjects)

@app.route('/admin/manage-notes')
@login_required
def manage_notes():
    notes = Note.query.order_by(Note.upload_date.desc()).all()
    
    # Format file sizes
    for note in notes:
        note.formatted_size = format_file_size(note.file_size) if note.file_size else "Unknown"
    
    return render_template('manage_notes.html', notes=notes)

@app.route('/admin/delete-note/<int:note_id>')
@login_required
def delete_note(note_id):
    note = Note.query.get_or_404(note_id)
    
    # Delete file from filesystem
    try:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], note.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
    except:
        pass
    
    # Delete from database
    db.session.delete(note)
    db.session.commit()
    
    flash('Note deleted successfully', 'success')
    return redirect(url_for('manage_notes'))

@app.route('/admin/manage-subjects')
@login_required
def manage_subjects():
    subjects = Subject.query.all()
    return render_template('manage_subjects.html', subjects=subjects)

@app.route('/admin/add-subject', methods=['POST'])
@login_required
def add_subject():
    name = request.form.get('name')
    description = request.form.get('description')
    
    if not name:
        flash('Subject name is required', 'error')
        return redirect(url_for('manage_subjects'))
    
    if Subject.query.filter_by(name=name).first():
        flash('Subject already exists', 'error')
        return redirect(url_for('manage_subjects'))
    
    subject = Subject(name=name, description=description)
    db.session.add(subject)
    db.session.commit()
    
    flash('Subject added successfully', 'success')
    return redirect(url_for('manage_subjects'))

@app.route('/admin/delete-subject/<int:subject_id>')
@login_required
def delete_subject(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    
    # Check if subject has notes
    if subject.notes:
        flash('Cannot delete subject with existing notes', 'error')
        return redirect(url_for('manage_subjects'))
    
    db.session.delete(subject)
    db.session.commit()
    
    flash('Subject deleted successfully', 'success')
    return redirect(url_for('manage_subjects'))

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

if __name__ == '__main__':
    init_database()
    app.run(debug=True, host='0.0.0.0', port=5000)