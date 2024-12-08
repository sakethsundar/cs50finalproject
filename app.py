from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
from functools import wraps

# Initialize Flask application
app = Flask(__name__)

# Configuration settings
app.config['SECRET_KEY'] = 'your-secret-key'  # Used for session management and CSRF protection
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///neurocare.db'  # Database location

# Initialize database and migrations
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirects to login page if a non-authenticated user accesses restricted pages

# Models
class User(db.Model, UserMixin):
    """
    Represents a user in the system.
    Attributes:
    - `id`: Unique identifier for the user.
    - `username`: Login username (must be unique).
    - `password`: Hashed password for security.
    - `role`: Role of the user (e.g., Doctor, Patient, Caregiver, Admin).
    - `full_name`: Full name of the user.
    - `patient_id`: Optional ID for patients (unique).
    - `five_digit_id`: A unique 5-digit ID assigned to all users.
    - `diagnosis`: Optional field for storing a diagnosis description.
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    full_name = db.Column(db.String(150), nullable=False)
    patient_id = db.Column(db.String(5), unique=True, nullable=True)
    five_digit_id = db.Column(db.String(5), unique=True, nullable=False)
    diagnosis = db.Column(db.String(150), nullable=True)

class Diagnosis(db.Model):
    """
    Represents a medical diagnosis for a patient assigned by a doctor.
    Attributes:
    - `patient_id`: References the User table for the patient.
    - `doctor_id`: References the User table for the doctor assigning the diagnosis.
    - `condition`: Name of the diagnosed condition.
    - `severity`: Severity of the condition.
    - `date_assigned`: The date the diagnosis was made.
    """
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    condition = db.Column(db.String(150), nullable=False)
    severity = db.Column(db.String(50), nullable=False)
    date_assigned = db.Column(db.Date, default=date.today)

    # Relationships for easy access
    patient = db.relationship('User', foreign_keys=[patient_id], backref='diagnoses_as_patient')
    doctor = db.relationship('User', foreign_keys=[doctor_id], backref='diagnoses_as_doctor')

class SymptomLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    date = db.Column(db.Date, nullable=False)
    symptom = db.Column(db.String(150), nullable=False)
    severity = db.Column(db.Integer, nullable=False)

class PatientDoctor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    doctor_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class PatientCaregiver(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    caregiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    message_content = db.Column(db.String(500), nullable=False)
    date_sent = db.Column(db.Date, default=date.today)

class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    date = db.Column(db.Date, nullable=False)
    time = db.Column(db.Time, nullable=False)
    appointment_type = db.Column(db.String(50), nullable=False)  # "In-Person" or "Telehealth"
    status = db.Column(db.String(50), default="Scheduled")  # "Scheduled", "Completed", "Cancelled"

class Availability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    date = db.Column(db.Date, nullable=False)
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)

class MedicationLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    medication_name = db.Column(db.String(150), nullable=False)
    dosage = db.Column(db.Integer, nullable=False)
    date_taken = db.Column(db.Date, default=date.today)


# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Role-based access control
def role_required(required_role):
    def decorator(func):
        @wraps(func)
        @login_required
        def wrapper(*args, **kwargs):
            if current_user.role != required_role:
                abort(403)  # Forbidden
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Routes
@app.route('/')
def home():
    if current_user.is_authenticated:
        # Redirect to the user's respective dashboard based on role
        if current_user.role == 'Doctor':
            return redirect(url_for('doctor_dashboard'))
        elif current_user.role == 'Patient':
            return redirect(url_for('patient_dashboard'))
        elif current_user.role == 'Caregiver':
            return redirect(url_for('caregiver_dashboard'))
    return render_template('index.html')  # Accessible only when logged out

import random

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['full_name']
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        # Check if the username already exists
        if User.query.filter_by(username=username).first():
            flash('Error: Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        # Hash the password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Generate a unique 5-digit ID for all users
        five_digit_id = str(random.randint(10000, 99999))
        while User.query.filter_by(five_digit_id=five_digit_id).first():
            five_digit_id = str(random.randint(10000, 99999))

        # Assign the 5-digit ID to the appropriate field
        if role == "Patient":
            patient_id = five_digit_id  # For patients, this will also serve as the patient ID
        else:
            patient_id = None  # Non-patients won't have a patient ID

        # Create a new user
        new_user = User(
            username=username,
            password=hashed_password,
            role=role,
            full_name=full_name,
            patient_id=patient_id,  # Only patients have this field populated
            five_digit_id=five_digit_id  # All roles will have a 5-digit ID
        )
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if username exists
        user = User.query.filter_by(username=username).first()
        if not user:
            flash('Error: Username does not exist.', 'danger')
            return redirect(url_for('login'))

        # Check if password is valid
        if not check_password_hash(user.password, password):
            flash('Error: Invalid password.', 'danger')
            return redirect(url_for('login'))

        # Log the user in
        login_user(user)
        flash('Logged in successfully!', 'success')

        # Redirect based on user role
        if current_user.role == 'Doctor':
            return redirect(url_for('doctor_dashboard'))
        elif current_user.role == 'Patient':
            return redirect(url_for('patient_dashboard'))
        elif current_user.role == 'Caregiver':
            return redirect(url_for('caregiver_dashboard'))
        else:
            return redirect(url_for('home'))

    return render_template('login.html')
@app.route('/send_message', methods=['POST'])
@login_required
@role_required('Doctor')
def send_message():
    patient_id = request.form.get('patient_id')
    message_content = request.form.get('message')

    # Validate input
    if not patient_id or not message_content:
        flash("Patient ID and message content are required.", "danger")
        return redirect(url_for('doctor_dashboard'))

    # Check if the patient exists
    patient = User.query.filter_by(id=patient_id, role='Patient').first()
    if not patient:
        flash("Patient not found or invalid ID.", "danger")
        return redirect(url_for('doctor_dashboard'))

    # Create and save the message
    new_message = Message(
        sender_id=current_user.id,
        receiver_id=patient.id,
        message_content=message_content,
        date_sent=datetime.utcnow()
    )
    db.session.add(new_message)
    db.session.commit()

    flash(f"Message sent to {patient.full_name} successfully.", "success")
    return redirect(url_for('doctor_dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/doctor_dashboard')
@role_required('Doctor')
def doctor_dashboard():
    # Fetch patients assigned to the current doctor
    assignments = PatientDoctor.query.filter_by(doctor_id=current_user.id).all()
    assigned_patients = [User.query.get(assignment.patient_id) for assignment in assignments]

    return render_template('doctor_dashboard.html', patients=assigned_patients)

@app.route('/assign_patient', methods=['POST'])
@role_required('Doctor')
def assign_patient():
    patient_id = request.form['patient_id']

    # Fetch the patient using the 5-digit patient_id
    patient = User.query.filter_by(patient_id=patient_id, role="Patient").first()
    if not patient:
        flash('Error: Patient with that ID does not exist.', 'danger')
        return redirect(url_for('doctor_dashboard'))

    # Check if this patient is already assigned to the doctor
    existing_assignment = PatientDoctor.query.filter_by(patient_id=patient.id, doctor_id=current_user.id).first()
    if existing_assignment:
        flash(f'Patient {patient.full_name} is already assigned to you.', 'warning')
        return redirect(url_for('doctor_dashboard'))

    # Create a new PatientDoctor assignment
    new_assignment = PatientDoctor(patient_id=patient.id, doctor_id=current_user.id)
    db.session.add(new_assignment)
    db.session.commit()

    flash(f'Patient {patient.full_name} (ID: {patient.patient_id}) assigned successfully!', 'success')
    return redirect(url_for('doctor_dashboard'))

@app.route('/assign_caregiver_to_patient', methods=['POST'])
@role_required('Doctor')
def assign_caregiver_to_patient():
    patient_id = request.form['patient_id']  # 5-digit Patient ID
    caregiver_id = request.form['caregiver_id']  # 5-digit Caregiver ID

    # Check if the patient exists
    patient = User.query.filter_by(patient_id=patient_id, role='Patient').first()
    if not patient:
        flash('Invalid Patient ID.', 'danger')
        return redirect(url_for('doctor_dashboard'))

    # Check if the caregiver exists
    caregiver = User.query.filter_by(five_digit_id=caregiver_id, role='Caregiver').first()
    if not caregiver:
        flash('Invalid Caregiver ID.', 'danger')
        return redirect(url_for('doctor_dashboard'))

    # Check if the patient is already assigned to the caregiver
    existing_assignment = PatientCaregiver.query.filter_by(patient_id=patient.id, caregiver_id=caregiver.id).first()
    if existing_assignment:
        flash('This patient is already assigned to the caregiver.', 'warning')
        return redirect(url_for('doctor_dashboard'))

    # Create a new assignment
    assignment = PatientCaregiver(patient_id=patient.id, caregiver_id=caregiver.id)
    db.session.add(assignment)
    db.session.commit()

    flash(f'Caregiver {caregiver.full_name} (ID: {caregiver.five_digit_id}) assigned to patient {patient.full_name} (ID: {patient.patient_id}) successfully!', 'success')
    return redirect(url_for('doctor_dashboard'))


import matplotlib.pyplot as plt
from io import BytesIO
import base64

import matplotlib.pyplot as plt
from io import BytesIO
import base64
import seaborn as sns  # For better color palettes

@app.route('/view_patient_logs/<int:patient_id>')
@login_required
def view_patient_logs(patient_id):
    # Fetch the patient
    patient = User.query.get_or_404(patient_id)
    if patient.role != 'Patient':
        flash('Invalid patient ID.', 'danger')
        return redirect(url_for('home'))

    # Fetch symptom logs for the patient
    logs = SymptomLog.query.filter_by(user_id=patient.id).order_by(SymptomLog.date.asc()).all()

    # Group logs by symptom
    grouped_logs = {}
    for log in logs:
        if log.symptom not in grouped_logs:
            grouped_logs[log.symptom] = {"dates": [], "severities": []}
        grouped_logs[log.symptom]["dates"].append(log.date)
        grouped_logs[log.symptom]["severities"].append(log.severity)

    # Generate Matplotlib plots
    plot_urls = []
    for symptom, data in grouped_logs.items():
        # Create a Matplotlib figure
        fig, ax = plt.subplots(figsize=(8, 5))
        sns.lineplot(x=data["dates"], y=data["severities"], marker='o', color='mediumblue', ax=ax)

        # Add aesthetics
        ax.set_title(f"{symptom} Severity Over Time", fontsize=16, fontweight='bold', color='navy')
        ax.set_xlabel("Date", fontsize=12, fontweight='bold')
        ax.set_ylabel("Severity (1-10)", fontsize=12, fontweight='bold')
        ax.set_ylim(0, 10)
        ax.tick_params(axis='both', which='major', labelsize=10)
        ax.grid(visible=True, linestyle='--', linewidth=0.7, alpha=0.7)

        # Rotate x-axis labels for better readability
        plt.xticks(rotation=45, ha='right')

        # Save the plot to a BytesIO object
        img = BytesIO()
        plt.savefig(img, format='png', bbox_inches='tight')
        img.seek(0)
        plt.close(fig)

        # Encode the image to base64 and append to plot_urls
        plot_url = base64.b64encode(img.getvalue()).decode('utf-8')
        plot_urls.append(plot_url)

    return render_template('view_patient_logs.html', patient=patient, logs=logs, plot_urls=plot_urls)


@app.route('/patient_dashboard')
@role_required('Patient')
def patient_dashboard():
    doctor_assignment = PatientDoctor.query.filter_by(patient_id=current_user.id).first()
    doctor_name = None
    if doctor_assignment:
        doctor = User.query.get(doctor_assignment.doctor_id)
        doctor_name = doctor.full_name if doctor else "Not Assigned"

    logs = SymptomLog.query.filter_by(user_id=current_user.id).all()
    diagnoses = Diagnosis.query.filter_by(patient_id=current_user.id).all()
    messages = Message.query.filter_by(receiver_id=current_user.id).order_by(Message.date_sent.desc()).all()
    medications = MedicationLog.query.filter_by(patient_id=current_user.id).order_by(MedicationLog.date_taken.desc()).all()

    return render_template(
        'patient_dashboard.html',
        logs=logs,
        diagnoses=diagnoses,
        messages=messages,
        medications=medications,
        doctor_name=doctor_name
    )

from datetime import datetime

@app.route('/log_symptom', methods=['GET', 'POST'])
@login_required
def log_symptom():
    if current_user.role != 'Patient':
        flash('Access denied. Only patients can log symptoms.', 'danger')
        return redirect(url_for('home'))

    # Define possible symptoms
    symptoms = ['Tremors', 'Fatigue', 'Cognitive Lapses', 'Muscle Weakness', 'Balance Issues']

    if request.method == 'POST':
        symptom = request.form['symptom']
        severity = int(request.form['severity'])
        date = request.form['date']

        # Convert the date string to a datetime object
        try:
            date = datetime.strptime(date, '%Y-%m-%d')
        except ValueError:
            flash('Invalid date format. Please use YYYY-MM-DD.', 'danger')
            return redirect(url_for('log_symptom'))

        # Log the symptom
        new_log = SymptomLog(user_id=current_user.id, symptom=symptom, severity=severity, date=date)
        db.session.add(new_log)
        db.session.commit()

        flash('Symptom logged successfully!', 'success')
        return redirect(url_for('patient_dashboard'))

    return render_template('log_symptom.html', symptoms=symptoms)

@app.route('/caregiver_dashboard')
@role_required('Caregiver')
def caregiver_dashboard():
    # Get assigned patients
    patients = db.session.query(User).join(PatientCaregiver, User.id == PatientCaregiver.patient_id) \
                   .filter(PatientCaregiver.caregiver_id == current_user.id).all()

    # Get diagnoses for assigned patients
    diagnoses = []
    for patient in patients:
        patient_diagnoses = Diagnosis.query.filter_by(patient_id=patient.id).all()
        for diagnosis in patient_diagnoses:
            diagnoses.append({
                "patient_name": patient.full_name,
                "patient_id": patient.patient_id,
                "condition": diagnosis.condition,
                "severity": diagnosis.severity,
                "assigned_by": User.query.get(diagnosis.doctor_id).full_name if diagnosis.doctor_id else "Unknown",
                "date_assigned": diagnosis.date_assigned
            })

    # Get messages sent to assigned patients
    messages = []
    for patient in patients:
        patient_messages = Message.query.filter_by(receiver_id=patient.id).all()
        for message in patient_messages:
            messages.append({
                "patient_name": patient.full_name,
                "patient_id": patient.patient_id,
                "sender": User.query.get(message.sender_id).full_name if message.sender_id else "Unknown",
                "message_content": message.message_content,
                "date_sent": message.date_sent
            })

    return render_template('caregiver_dashboard.html', patients=patients, caregiver_id=current_user.five_digit_id,
                           diagnoses=diagnoses, messages=messages)

@app.route('/calendar_events')
@login_required
def calendar_events():
    events = []

    # Fetch availability for assigned doctor (Patients only)
    if current_user.role == 'Patient':
        # Fetch assigned doctor
        doctor_assignment = PatientDoctor.query.filter_by(patient_id=current_user.id).first()
        if doctor_assignment:
            availabilities = Availability.query.filter_by(doctor_id=doctor_assignment.doctor_id).all()
            for availability in availabilities:
                events.append({
                    "title": "Doctor Available",
                    "start": f"{availability.date}T{availability.start_time}",
                    "end": f"{availability.date}T{availability.end_time}",
                    "color": "green",
                    "display": "background"  # Makes it non-interactive
                })

    # Fetch appointments
    if current_user.role == 'Doctor':
        appointments = Appointment.query.filter_by(doctor_id=current_user.id).all()
    elif current_user.role == 'Patient':
        appointments = Appointment.query.filter_by(patient_id=current_user.id).all()
    else:
        appointments = []

    for appointment in appointments:
        doctor_name = None
        patient_name = None

        # Fetch doctor and patient names
        if current_user.role == 'Doctor':
            patient = User.query.filter_by(id=appointment.patient_id).first()
            patient_name = patient.full_name if patient else f"Patient: {appointment.patient_id}"
        elif current_user.role == 'Patient':
            doctor = User.query.filter_by(id=appointment.doctor_id).first()
            doctor_name = doctor.full_name if doctor else f"Doctor: {appointment.doctor_id}"

        # Add event to calendar
        events.append({
            "title": f"Doctor: {doctor_name}" if doctor_name else f"Patient: {patient_name}",
            "start": f"{appointment.date}T{appointment.time}",
            "description": f"{appointment.appointment_type}",
            "color": "blue",
        })

    return jsonify(events)
    
@app.route('/create_appointment', methods=['POST'])
@login_required
def create_appointment():
    if current_user.role != 'Patient':  # Restrict to patients only
        flash('Only patients can book appointments.', 'danger')
        return redirect(url_for('view_calendar'))

    data = request.json
    try:
        doctor_id = data.get('doctor_id')
        date_time = data.get('date_time')  # ISO format: YYYY-MM-DDTHH:MM:SS
        appointment_type = data.get('appointment_type')

        # Parse the date and time
        appointment_datetime = datetime.fromisoformat(date_time)
        appointment_date = appointment_datetime.date()
        appointment_time = appointment_datetime.time()

        # Check if doctor exists
        doctor = User.query.filter_by(id=doctor_id, role='Doctor').first()
        if not doctor:
            return jsonify({"success": False, "message": "Invalid doctor ID"}), 400

        # Create appointment
        appointment = Appointment(
            doctor_id=doctor_id,
            patient_id=current_user.id,
            date=appointment_date,
            time=appointment_time,
            appointment_type=appointment_type
        )
        db.session.add(appointment)
        db.session.commit()
        return jsonify({"success": True, "message": "Appointment booked successfully!"}), 201
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 400

@app.route('/set_availability', methods=['POST'])
@role_required('Doctor')
def set_availability():
    data = request.json
    try:
        date = data.get('date')
        start_time = data.get('start_time')
        end_time = data.get('end_time')

        # Parse date and time
        availability_date = datetime.strptime(date, '%Y-%m-%d').date()
        start_time_obj = datetime.strptime(start_time, '%H:%M').time()  # Fixed time format
        end_time_obj = datetime.strptime(end_time, '%H:%M').time()      # Fixed time format

        # Create or update availability
        availability = Availability(
            doctor_id=current_user.id,
            date=availability_date,
            start_time=start_time_obj,
            end_time=end_time_obj
        )
        db.session.add(availability)
        db.session.commit()
        return jsonify({"success": True, "message": "Availability set successfully!"}), 201
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 400
@app.route('/view_calendar')
@login_required
def view_calendar():
    assigned_doctor = None
    if current_user.role == 'Patient':
        doctor_assignment = PatientDoctor.query.filter_by(patient_id=current_user.id).first()
        if doctor_assignment:
            assigned_doctor = User.query.get(doctor_assignment.doctor_id)

    doctors = User.query.filter_by(role='Doctor').all() if current_user.role == 'Doctor' else []
    return render_template('view_calendar.html', doctors=doctors, assigned_doctor=assigned_doctor)

from random import choice, randint
from datetime import timedelta, datetime

@app.route('/seed_users_and_logs')
def seed_users_and_logs():
    from random import randint, choice
    from datetime import datetime, timedelta

    # Predefined users with diverse names, roles, and diagnoses for patients
    users = [
        {"username": "dr_williams", "password": "docpass1", "role": "Doctor", "full_name": "Sarah Williams"},
        {"username": "dr_anderson", "password": "docpass2", "role": "Doctor", "full_name": "Michael Anderson"},
        {"username": "dr_taylor", "password": "docpass3", "role": "Doctor", "full_name": "Emily Taylor"},
        {"username": "pat_jones", "password": "patpass1", "role": "Patient", "full_name": "Christopher Jones"},
        {"username": "pat_clark", "password": "patpass2", "role": "Patient", "full_name": "Sophia Clark"},
        {"username": "pat_martin", "password": "patpass3", "role": "Patient", "full_name": "Liam Martin"},
        {"username": "pat_lee", "password": "patpass4", "role": "Patient", "full_name": "Olivia Lee"},
        {"username": "pat_kim", "password": "patpass5", "role": "Patient", "full_name": "Ethan Kim"},
        {"username": "pat_garcia", "password": "patpass6", "role": "Patient", "full_name": "Isabella Garcia"},
        {"username": "care_smith", "password": "carepass1", "role": "Caregiver", "full_name": "Anna Smith"},
        {"username": "care_brown", "password": "carepass2", "role": "Caregiver", "full_name": "David Brown"},
        {"username": "care_johnson", "password": "carepass3", "role": "Caregiver", "full_name": "Laura Johnson"},
    ]

    # Conditions and severities
    diagnoses = [
        {"condition": "Parkinson's Disease", "severity": "Mild"},
        {"condition": "Multiple Sclerosis", "severity": "Moderate"},
        {"condition": "Alzheimer's Disease", "severity": "Severe"},
        {"condition": "Parkinson's Disease", "severity": "Severe"},
        {"condition": "Multiple Sclerosis", "severity": "Mild"},
        {"condition": "Alzheimer's Disease", "severity": "Moderate"},
    ]

    # Medications specific to conditions
    medications = {
        "Parkinson's Disease": "Levodopa",
        "Multiple Sclerosis": "Interferon Beta",
        "Alzheimer's Disease": "Donepezil"
    }

    # Seed Users
    user_objects = {}
    for user_data in users:
        # Hash password
        hashed_password = generate_password_hash(user_data["password"], method='pbkdf2:sha256')

        # Generate unique 5-digit ID for all users
        five_digit_id = str(randint(10000, 99999))
        while User.query.filter_by(five_digit_id=five_digit_id).first():
            five_digit_id = str(randint(10000, 99999))

        # Generate patient ID if the user is a patient
        patient_id = None
        if user_data["role"] == "Patient":
            patient_id = str(randint(10000, 99999))
            while User.query.filter_by(patient_id=patient_id).first():
                patient_id = str(randint(10000, 99999))

        # Create and add user
        new_user = User(
            username=user_data["username"],
            password=hashed_password,
            role=user_data["role"],
            full_name=user_data["full_name"],
            patient_id=patient_id,
            five_digit_id=five_digit_id
        )
        db.session.add(new_user)
        user_objects[user_data["username"]] = new_user

    db.session.commit()

    # Define patient assignments to doctors and caregivers
    assignments = {
        "pat_jones": {"doctor": "dr_williams", "caregiver": "care_smith", "diagnosis": 0},
        "pat_clark": {"doctor": "dr_anderson", "caregiver": "care_brown", "diagnosis": 1},
        "pat_martin": {"doctor": "dr_taylor", "caregiver": "care_johnson", "diagnosis": 2},
        "pat_lee": {"doctor": "dr_williams", "caregiver": "care_brown", "diagnosis": 3},
        "pat_kim": {"doctor": "dr_anderson", "caregiver": "care_johnson", "diagnosis": 4},
        "pat_garcia": {"doctor": "dr_taylor", "caregiver": "care_smith", "diagnosis": 5},
    }

    # Seed Assignments and Logs
    symptoms = ['Tremors', 'Fatigue', 'Cognitive Lapses', 'Muscle Weakness', 'Balance Issues']
    for patient_username, assignment in assignments.items():
        patient = user_objects[patient_username]
        doctor = user_objects[assignment["doctor"]]
        caregiver = user_objects[assignment["caregiver"]]

        # Create PatientDoctor and PatientCaregiver relationships
        doctor_assignment = PatientDoctor(patient_id=patient.id, doctor_id=doctor.id)
        caregiver_assignment = PatientCaregiver(patient_id=patient.id, caregiver_id=caregiver.id)
        db.session.add(doctor_assignment)
        db.session.add(caregiver_assignment)

        # Assign a diagnosis
        diag = diagnoses[assignment["diagnosis"]]
        new_diagnosis = Diagnosis(
            patient_id=patient.id,
            doctor_id=doctor.id,
            condition=diag["condition"],
            severity=diag["severity"],
            date_assigned=datetime.utcnow().date()
        )
        db.session.add(new_diagnosis)

        # Seed extended symptom logs for the patient (6 months of data)
        start_date = datetime.utcnow().date() - timedelta(days=180)
        for i in range(60):  # Roughly every 3 days
            log_date = start_date + timedelta(days=i * 3)
            new_log = SymptomLog(
                user_id=patient.id,
                date=log_date,
                symptom=choice(symptoms),
                severity=randint(1, 10)
            )
            db.session.add(new_log)

        # Seed medication logs (3 months of data, every 2 days)
        medication_name = medications.get(diag["condition"], "General Medicine")
        dosage = randint(10, 50)
        start_date_medication = datetime.utcnow().date() - timedelta(days=90)
        for j in range(45):  # Every 2 days
            log_date_medication = start_date_medication + timedelta(days=j * 2)
            new_medication_log = MedicationLog(
                patient_id=patient.id,
                medication_name=medication_name,
                dosage=f"{dosage} mg",
                date_taken=log_date_medication
            )
            db.session.add(new_medication_log)

    db.session.commit()

    return "Seeded users, diagnoses, symptom logs, medication logs, and assignments successfully!"
@app.route('/assign_diagnosis', methods=['POST'])
@role_required('Doctor')
def assign_diagnosis():
    patient_id = request.form['patient_id']
    condition = request.form['condition']
    severity = request.form['severity']

    # Check if the patient exists
    patient = User.query.filter_by(patient_id=patient_id, role='Patient').first()
    if not patient:
        flash('Error: Patient with that ID does not exist.', 'danger')
        return redirect(url_for('doctor_dashboard'))

    # Create and save the diagnosis
    diagnosis = Diagnosis(
        patient_id=patient.id,
        doctor_id=current_user.id,
        condition=condition,
        severity=severity
    )
    db.session.add(diagnosis)
    db.session.commit()

    flash(f"Diagnosis '{condition}' with severity '{severity}' assigned to {patient.full_name}.", 'success')
    return redirect(url_for('doctor_dashboard'))

@app.route('/exercises/<condition>')
@role_required('Patient')
def exercises(condition):
    # Define videos for each condition
    exercise_videos = {
        "Parkinson's Disease": {
            "title": "Parkinson's Disease Exercise Videos",
            "videos": [
                "https://www.youtube.com/embed/video1",
                "https://www.youtube.com/embed/video2",
                "https://www.youtube.com/embed/video3",
                "https://www.youtube.com/embed/video4",
            ],
        },
        "Multiple Sclerosis": {
            "title": "Multiple Sclerosis Exercise Videos",
            "videos": [
                "https://www.youtube.com/embed/video5",
                "https://www.youtube.com/embed/video6",
                "https://www.youtube.com/embed/video7",
                "https://www.youtube.com/embed/video8",
            ],
        },
        "Alzheimer's Disease": {
            "title": "Alzheimer's Exercise Videos",
            "videos": [
                "https://www.youtube.com/embed/video9",
                "https://www.youtube.com/embed/video10",
                "https://www.youtube.com/embed/video11",
                "https://www.youtube.com/embed/video12",
            ],
        },
    }

    # Check if the condition is valid
    if condition not in exercise_videos:
        flash("Invalid condition.", "danger")
        return redirect(url_for("patient_dashboard"))

    return render_template("condition_exercises.html", content=exercise_videos[condition])


@app.route('/medications/<condition>')
@role_required('Patient')
def view_medications(condition):
    # Define medication recommendations
    medication_recommendations = {
        "Parkinson's Disease": [
            {"name": "Levodopa", "description": "Improves motor function by replenishing dopamine levels."},
            {"name": "Carbidopa", "description": "Enhances the effect of Levodopa and reduces side effects."},
            {"name": "MAO-B inhibitors", "description": "Helps prevent the breakdown of dopamine."},
            {"name": "Amantadine", "description": "Reduces involuntary movements."}
        ],
        "Multiple Sclerosis": [
            {"name": "Interferon beta", "description": "Reduces the frequency of relapses."},
            {"name": "Glatiramer acetate", "description": "Helps prevent immune system attacks on nerves."},
            {"name": "Ocrelizumab", "description": "Slows disease progression."},
            {"name": "Corticosteroids", "description": "Treats acute relapses."}
        ],
        "Alzheimer's Disease": [
            {"name": "Donepezil", "description": "Improves memory and cognitive function."},
            {"name": "Rivastigmine", "description": "Enhances communication between nerve cells."},
            {"name": "Memantine", "description": "Regulates glutamate activity to reduce symptoms."},
            {"name": "Cholinesterase inhibitors", "description": "Helps manage mild to moderate symptoms."}
        ]
    }

    # Check if the provided condition exists in recommendations
    if condition not in medication_recommendations:
        flash("Invalid condition. Please contact your doctor for more information.", "danger")
        return redirect(url_for('patient_dashboard'))

    # Prepare the content for rendering
    content = {
        "title": f"Medications for {condition}",
        "medications": medication_recommendations[condition],
    }

    # Render the medications page
    return render_template('condition_medications.html', content=content)

@app.route('/log_medication', methods=['GET', 'POST'])
@role_required('Patient')
def log_medication():
    # Fetch all diagnoses for the current patient
    diagnoses = Diagnosis.query.filter_by(patient_id=current_user.id).all()

    # Aggregate medications based on the patient's diagnoses
    condition_medication_map = {
        "Parkinson's Disease": ["Levodopa", "Ropinirole"],
        "Multiple Sclerosis": ["Ocrelizumab", "Fingolimod"],
        "Alzheimer's": ["Donepezil", "Memantine"]
    }
    medications = []
    for diagnosis in diagnoses:
        if diagnosis.condition in condition_medication_map:
            medications.extend(condition_medication_map[diagnosis.condition])

    if request.method == 'POST':
        medication_name = request.form['medication_name']
        dosage = request.form['dosage']

        if not medication_name or not dosage:
            flash("Both medication and dosage are required.", "danger")
            return redirect(url_for('log_medication'))

        # Log the medication
        new_log = MedicationLog(
            patient_id=current_user.id,
            medication_name=medication_name,
            dosage=f"{dosage} mg"
        )
        db.session.add(new_log)
        db.session.commit()

        flash(f"Logged medication: {medication_name} ({dosage}).", "success")
        return redirect(url_for('patient_dashboard'))

    return render_template('log_medication.html', medications=medications)

@app.route('/medication_logs/<int:patient_id>')
@login_required
def medication_logs(patient_id):
    # Check if the current user is a patient viewing their own logs
    if current_user.role == "Patient" and current_user.id == patient_id:
        logs = MedicationLog.query.filter_by(patient_id=patient_id).order_by(MedicationLog.date_taken.desc()).all()
        return render_template('medication_logs.html', logs=logs, patient=current_user, is_doctor=False)

    # Check if the current user is a doctor assigned to the patient
    if current_user.role == "Doctor":
        assignment = PatientDoctor.query.filter_by(doctor_id=current_user.id, patient_id=patient_id).first()
        if not assignment:
            flash("You do not have permission to view this patient's medication logs.", "danger")
            return redirect(url_for('doctor_dashboard'))
        
        patient = User.query.get(patient_id)
        logs = MedicationLog.query.filter_by(patient_id=patient_id).order_by(MedicationLog.date_taken.desc()).all()
        return render_template('medication_logs.html', logs=logs, patient=patient, is_doctor=True)

    # Deny access for unauthorized users
    flash("You do not have permission to view this page.", "danger")
    return redirect(url_for('home'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Initialize the database
    app.run(debug=True)


