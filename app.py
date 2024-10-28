import os, re, mysql.connector
from http.client import responses
from traceback import print_tb

from flask import Flask, flash, redirect, render_template, request, session, jsonify, url_for
from pdfminer.high_level import extract_text
from openai import OpenAI

from dotenv import load_dotenv  # New import to load environment variables

import mysql.connector
import logging
import json
import ast
# Load environment variables from .env file
load_dotenv()  # New line to load environment variables

# Access the API key from the environment variable

openai_api_key = os.getenv("OPEN_API_KEY")

# Check if the API key is present
if not openai_api_key:
    raise ValueError("API Key not found. Ensure that OPENAI_API_KEY is set in the .env file.")  # Error handling if API key is missing

# Initialize OpenAI client with the API key
client = OpenAI(api_key=openai_api_key)  # Use the environment variable API key

app = Flask(__name__)
app.secret_key = 'your_secret_key'

gunicorn_error_logger = logging.getLogger('gunicorn.error')
app.logger.handlers.extend(gunicorn_error_logger.handlers)
app.logger.setLevel(logging.DEBUG)
app.logger.debug('Logging works')

vulTemplete = {
    "cve":"",
    "description":"",
    "date_found":"",
    "systems_affected":"",
    "severity_rating":"",
    "remediation_plan":"",
    "cost_estimate":"",
    "profession_needed":""
}

@DeprecationWarning
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

# config to connect database
db_config = {
    'user': 'ipro_admin',
    'password': 'Iproadmin$497',
    'host': 'ipro-497-db-instance-1.crhoiczd7use.us-east-1.rds.amazonaws.com', 
    'database': 'ipro497db',
    'port': '3306'
}

# get connnection function 
def db_connection():
    return mysql.connector.connect(**db_config)

@app.route('/')
def home():
    return redirect(url_for('index'))

#moved all of the login() code to index() and it kinda just works
@app.route('/index', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = db_connection()
        cur = conn.cursor()

        try:
            cur.execute("SELECT * from users WHERE email = %s and password = %s", [email, password])
            user = cur.fetchone()
            if user is None:
                flash('Invalid credentials, please try again.', 'error')
                return redirect(url_for('index'))
            else:
                session['username'] = user[2]  # type: ignore
                session['user_id'] = user[0]
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))

        except mysql.connector.Error as err:
            flash('Invalid credentials, please try again.', 'error')

            return redirect(url_for('index'))

        finally:
            cur.close()
            conn.close()

    return render_template('index.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
      first = request.form.get('First')
      last = request.form.get('Last')
      email = request.form.get('Email')
      password = request.form.get('Password')

      conn = db_connection()
      cur = conn.cursor()

      try:
        
        cur.execute('INSERT INTO users (first_name, last_name, email, password) VALUES (%s, %s, %s, %s)', (first, last, email, password))
        conn.commit()
        return redirect(url_for('login'))
      
      except mysql.connector.Error as err: 
        flash('An error has been detected; this email might have been used')
        return redirect(url_for('register')) 
      
      finally:
        cur.close()
        conn.close()
      
    return render_template('signup.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'], cves=None, analysis=None)
    else:
        flash('You are not logged in.', 'error')
        return redirect(url_for('index'))

from flask import jsonify

@app.route('/upload_file', methods=['POST'])
def upload_file():
    filename = None
    try:
        print("Uploading file...")
        if 'username' not in session:
            return jsonify({'error': 'You are not logged in.'}), 401

        if 'pentest_file' not in request.files:
            return jsonify({'error': 'No file part'}), 400

        file = request.files['pentest_file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        filename = os.path.join(app.config['UPLOAD_FOLDER'], file.filename) 

      # -----insert report info to database---------------------------------------------------------------------------------------------------------
        conn = db_connection()
        cur = conn.cursor()
        user_id = session['user_id']
        try:
            cur.execute("INSERT INTO report (title, user_id) VALUES (%s, %s)", (filename, user_id))
            conn.commit()
            print("file uploaded to database")
        except mysql.connector.Error as err:
            flash('Invalid credentials, please try again.', 'error')
        finally:
            cur.execute("SELECT report_id from report WHERE title = %s and user_id = %s  ORDER BY report_id DESC LIMIT 1", (filename, user_id) ) # give most recent entre
            reportID = cur.fetchone()
            session['report_id'] = reportID[0]  # type: ignore
            cur.close()
            conn.close()
      # -------------------------------------------------------------------------------------------------------------------------------
        file.save(filename)

    except Exception as e:
        # Log the error and return a JSON error response
        print(f"Error during file upload: {e}")
        return jsonify({'error': 'An error occurred during file processing.'}), 500

    finally:
    # Extract CVEs from the file
      cves = extract_cves(filename)
      categorized_cves = categorize_cves(cves)

      print(f"using these CVES: {cves}")

      vuls = []
      for cve in cves:
          newVel = vulTemplete.copy()
          newVel['cve'] = cve
          vuls.append(newVel)

      print(f"getting infomation for {len(vuls)} vulnerabilities")
      # print(vuls)
      vuls = extractVulnerabilities(vuls)


     #  print(vuls)
      print("Finished Extracted")
          # print(vuls)

          # Store vulnerabilities in the database
      store_in_database(vuls)

      # link_recent_vulnerabilities(vul_count)

          # Get ChatGPT analysis of the CVEs
          # analysis = get_chatgpt_analysis(cves)
      #return json.dumps(vuls, indent=2)
      #return
    vulJson = jsonify({'cves': categorized_cves, 'analysis': json.dumps(get_vulnerabilities(),indent=2)})
    #json.dumps(get_vulnerabilities(),indent=2)
    print(str(vulJson))
    return vulJson


# Function to extract CVEs from PDF or text file
def extract_cves(filepath):
    print("Extracting CVEs...")
    text = extract_from_pdf(filepath) if filepath.endswith('.pdf') else extract_from_txt(filepath)

    # Find all CVE patterns using regex
    cves = re.findall(CVE_REGEX, text)

    # Return unique CVEs

    # print(f"found CVES {cves}")
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
def store_in_database(vuls):
    conn = db_connection()
    cur = conn.cursor()
    report_id = session['report_id']

    # if not list (only one vul) make it a list of length 1 so it works with the for loop
    if not isinstance(vuls, list):
        vuls = [vuls]
    
    try:
      for vul in vuls:
          sqlStatement = f'''
              INSERT INTO vulnerability (cve, description, date_found, systems_affected, severity_rating, remediation_plan, cost_estimate, profession_needed)
              VALUES ("{vul['cve']}", "{vul['description']}", "{vul['date_found']}", "{vul['systems_affected']}", "{vul['severity_rating']}", "{vul['remediation_plan']}", "{vul['cost_estimate']}", "{vul['profession_needed']}")
          '''
          # print(sqlStatement)
          cur.execute(sqlStatement, )
          conn.commit()

  # -----link between report file and its vulnerability-------------------------------------------------------------------------------------------
          cur.execute("SELECT vulnerability_id FROM vulnerability ORDER BY vulnerability_id DESC LIMIT 1")
          vID = cur.fetchone()
          vulnID = vID[0] # type: ignore
          cur.execute("INSERT INTO report_vulnerability (report_id,vulnerability_id) VALUES (%s, %s)", (report_id, vulnID)) # type: ignore
          conn.commit()

          print(f"Connected vul_id {vulnID} to report id {report_id}, CVE: {vul['cve']}")
  # ------------------------------------------------------------------------------------------------------------------------

      print("added vulnerabilities to database")
      return len(vuls)
    except Exception as e:
        print(f"Could not upload to database, Error: {e}")

    finally:
      cur.close()
      conn.close()

@DeprecationWarning
# Function to get ChatGPT analysis of CVEs
def get_chatgpt_analysis(cves):
    if not cves:
        return "No CVEs found in the report."

    prompt = f"The following CVEs were extracted from a pentest report:\n{', '.join(cves)}. Output the following information, the CVE, Description of the CVE, Please give me a risk estimation, cost to fix estimate in dollars, and Time to Fix. Don't include any pleasantries"

    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "You are an expert in cybersecurity and CVE analysis."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=500
    )
    cve_analysis_array = response.choices[0].message.content.split('\n')

    return cve_analysis_array

# cve_data_list = []

# for cve_entry in cve_analysis_array:
#     # Use regex to extract the relevant parts for each CVE
#     cve_id = re.search(r'CVE-\d{4}-\d{4,7}', cve_entry)
#     cve_description = re.search(r'Description of CVE:\s*(.*)', cve_entry)
#     cost_to_fix = re.search(r'Cost to Fix CVE:\s*(.*)', cve_entry)
#     risk_rate = re.search(r'Risk Rate:\s*(high|medium|low)', cve_entry)
#     time_to_fix = re.search(r'Time to fix:\s*(.*)', cve_entry)

#     # Store each CVE's details in a dictionary
#     cve_data = {
#         'CVE_ID': cve_id.group(0) if cve_id else None,
#         'CVE_Description': cve_description.group(1) if cve_description else None,
#         'Cost_to_Fix': cost_to_fix.group(1) if cost_to_fix else None,
#         'Risk_Rate': risk_rate.group(1) if risk_rate else None,
#         'Time_to_Fix': time_to_fix.group(1) if time_to_fix else None
#     }


def extractVulnerabilities(vulnerabilities):
    #vulnerabilities = []

    # Open and read the PDF file
    #report_text = extract_from_pdf(filepath) if filepath.endswith('.pdf') else extract_from_txt(filepath)

    OpenAI_Responses = []
   # vulnerabilities = vulnerabilities[0:2] #reduce list entries for testing purposes
    for vul in vulnerabilities:
        # Prepare the messages for GPT-4 chat format
        messages = [
            {"role": "system",
             "content": 'You are a cybersecurity assistant'
             #json.dumps(vul)
             },
            {"role": "user",
             "content": f"Here is a JSON of a vulnerability:\n\n{json.dumps(vul)}\n\nPlease fill in the empty rows.  Please do not add extra test outside of the JSON"}
        ]

      #  print(messages)

        # Use OpenAI's ChatCompletion API to extract vulnerabilities
        response = client.chat.completions.create(
            model="gpt-4",  # Use the appropriate model
            messages=messages,
            max_tokens=1500,  # Adjust based on report size
            temperature=0.3
        )
       # print(response.choices[0].message.content)
        vulDict = ast.literal_eval(response.choices[0].message.content)
     #   print(vulDict)
        OpenAI_Responses.append(vulDict)
        #OpenAI_Responses.append(response.choices[0].message.content)

    return OpenAI_Responses

   # vulnerabilities_text = response['choices'][0]['message']['content']
   # vulnerabilities = vulnerabilities_text.strip().split('\n')

# Route to fetch vulnerabilities by report_id

@app.route('/report', methods=['GET'])
def get_vulnerabilities():
    conn = db_connection()
    cursor = conn.cursor()

    # this shit is complicated
    # query = """
    # SELECT v.name, v.severity, v.description, v.cve, v.systems, v.skill, v.parties, v.low_cost, v.high_cost
    # FROM report_vulnerability rv
    # JOIN report r ON rv.report_id = r.report_id
    # JOIN vulnerability v ON rv.vulnerability_id = v.vulnerability_id
    # WHERE r.report_id = %s;
    # """

    #I made the query really simple and it kinda just works
    #change the query so select all vulnerability with the right report ID (might not work)
    #simpleQuery = "SELECT * FROM vulnerability"

    reportID = [session['report_id']]
    simpleQuery = "SELECT v.* FROM vulnerability v JOIN report_vulnerability rv ON v.vulnerability_id = rv.vulnerability_id WHERE rv.report_id =%s"
    cursor.execute(simpleQuery, reportID)
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


    print(f'formated data {formatted_data}')

    return formatted_data
@app.route('/logout')
def logout():
    session.clear()
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
    app.run(host='0.0.0.0', port=8080, debug=True)
