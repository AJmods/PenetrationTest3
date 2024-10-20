from flask import Flask, render_template, request, redirect, url_for, flash
import mysql.connector

app = Flask(__name__)
app.secret_key = '20aB38Lu'

db_config = {
    'user': 'ipro_admin',
    'password': 'Iproadmin$497',
    'host': 'ipro-497-db-instance-1.crhoiczd7use.us-east-1.rds.amazonaws.com', 
    'database': 'ipro497db',
    'port': '3306'
}

def db_connection():
    return mysql.connector.connect(**db_config)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/')
def signup():
    return render_template('signup.html')

@app.route('/register', methods=['POST'])
def register():
    first = request.form['First']
    last = request.form['Last']
    email = request.form['Email']
    password = request.form['Password']

    conn = db_connection()
    curr = conn.cursor()
    try:
      curr.execute('INSERT INTO users (first_name, last_name, email, password) VALUES (%s, %s, %s, %s)', (first, last, email, password))
      conn.commit()
      flash('Welcome to Zebra!')
      return redirect(url_for('index'))
    except mysql.connector.Error as err: 
      flash('An error has been detected; this email might have been used or format is incorrect')
      return redirect(url_for('signup'))
    
    finally:
      curr.close()
      conn.close()
        

if __name__ == '__main__':
    app.run(debug=True)