import os
import re
import sqlite3
from flask import Flask, flash, redirect, render_template, request, session, url_for
from pdfminer.high_level import extract_text
from openai import OpenAI
from dotenv import load_dotenv  # New import to load environment variables
import mysql.connector

# Load environment variables from .env file
load_dotenv()  # New line to load environment variables

# Access the API key from the environment variable
openai_api_key = os.getenv("OPENAI_API_KEY")  # Fetch API key from environment

# Check if the API key is present
if not openai_api_key:
    raise ValueError("API Key not found. Ensure that OPENAI_API_KEY is set in the .env file.")  # Error handling if API key is missing

# Initialize OpenAI client with the API key
client = OpenAI(api_key=openai_api_key)  # Use the environment variable API key

app = Flask(__name__)
app.secret_key = 'your_secret_key'

def get_db_connection():
    conn = mysql.connector.connect(
        host="your-aws-rds-endpoint",
        user="your_db_user",
        password="your_password",
        database="your_db_name"
    )
    return conn
# Path to store uploaded files
UPLOAD_FOLDER = './uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Regex to match CVE patterns
CVE_REGEX = r'CVE-\d{4}-\d{4,7}'

# Dummy user data for login validation
users = {
    "admin": "Newsy",
    "user": "123"
}

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect('vulnerabilities.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve TEXT,
            description TEXT,
            date_found TEXT,
            systems_affected TEXT,
            severity_rating TEXT,
            remediation_plan TEXT,
            cost_estimate TEXT,
            profession_needed TEXT
        )
    ''')
    conn.commit()
    conn.close()

@app.route('/')
def home():
    return redirect(url_for('index'))

@app.route('/index', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users and users[username] == password:
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials, please try again.', 'error')

    return render_template('index.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'], cves=None, analysis=None)
    else:
        flash('You are not logged in.', 'error')
        return redirect(url_for('index'))

@app.route('/upload_file', methods=['POST'])
def upload_file():
    print("Uploading file...")
    if 'username' not in session:
        flash('You are not logged in.', 'error')
        return redirect(url_for('index'))

    if 'pentest_file' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('dashboard'))

    file = request.files['pentest_file']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('dashboard'))

    if file:
        filename = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filename)

        # Extract CVEs from the file
        cves = extract_cves(filename)
        categorized_cves = categorize_cves(cves)

        # Store vulnerabilities in the database
        store_in_database(categorized_cves)

        # Get ChatGPT analysis of the CVEs
        analysis = get_chatgpt_analysis(cves)

        return render_template('dashboard.html', username=session['username'], cves=categorized_cves, analysis=analysis)

# Function to extract CVEs from PDF or text file
def extract_cves(filepath):
    print("Extracting CVEs...")
    text = extract_from_pdf(filepath) if filepath.endswith('.pdf') else extract_from_txt(filepath)

    # Find all CVE patterns using regex
    cves = re.findall(CVE_REGEX, text)

    # Return unique CVEs
    return list(set(cves))

# Function to extract text from PDF
def extract_from_pdf(filepath):
    text = extract_text(filepath)
    return text

# Function to extract text from a plain text file
def extract_from_txt(filepath):
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        return f.read()

def categorize_cves(cves):
    categorized = []
    for cve in cves:
        category = 'Other'  # Default category if no match
        categorized.append({
            'id': cve,
            'description': 'Description of ' + cve,  # Add more details here
            'category': category
        })
    return categorized

# Function to store parsed vulnerabilities in the database
def store_in_database(cves):
    conn = sqlite3.connect('vulnerabilities.db')
    c = conn.cursor()

    for cve in cves:
        c.execute('''
            INSERT INTO vulnerabilities (cve, description, date_found, systems_affected, severity_rating, remediation_plan, cost_estimate, profession_needed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (cve['id'], cve['description'], None, None, None, None, None, None))

    conn.commit()
    conn.close()

# Function to get ChatGPT analysis of CVEs
def get_chatgpt_analysis(cves):
    if not cves:
        return "No CVEs found in the report."

    prompt = f"The following CVEs were extracted from a pentest report:\n{', '.join(cves)}. Can you provide detailed analysis of these CVEs including their description, systems affected, severity rating, and how to remediate them (cost estimate and profession needed)?"

    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "You are an expert in cybersecurity and CVE analysis."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=500
    )

    return response.choices[0].message.content
    
# Route to fetch vulnerabilities by report_id
@app.route('/report/<int:report_id>', methods=['GET'])
def get_vulnerabilities(report_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    query = """
    SELECT v.name, v.severity, v.description, v.cve, v.systems, v.skill, v.parties, v.low_cost, v.high_cost
    FROM report_vulnerability rv
    JOIN report r ON rv.report_id = r.report_id
    JOIN vulnerability v ON rv.vulnerability_id = v.vulnerability_id
    WHERE r.report_id = %s;
    """
    cursor.execute(query, (report_id,))
    vulnerabilities = cursor.fetchall()

    # Format data as JSON
    formatted_data = [
        {
            "name": row[0],
            "severity": row[1],
            "description": row[2],
            "cve": row[3],
            "systems": row[4],
            "skill": row[5],
            "parties": row[6],
            "low_cost": row[7],
            "high_cost": row[8],
        }
        for row in vulnerabilities
    ]

    cursor.close()
    conn.close()

    return jsonify(formatted_data)
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/profile')
def profile():
    if 'username' not in session:
        flash('You are not logged in.', 'error')
        return redirect(url_for('index'))
    return render_template('profile.html')

@app.route('/history')
def history():
    if 'username' not in session:
        flash('You are not logged in.', 'error')
        return redirect(url_for('index'))
    return render_template('history.html')

if __name__ == '__main__':
    init_db()  # Initialize the database on startup
    app.run(host='0.0.0.0', port=8080, debug=True)
