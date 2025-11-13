
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import os, json
from pathlib import Path

app = Flask(__name__)
app.secret_key = 'replace-this-with-a-secure-key'

DATA_FILE = Path(__file__).parent / "storage.json"

def load_data():
    if DATA_FILE.exists():
        return json.loads(DATA_FILE.read_text(encoding='utf-8') or "{}")
    return {"admins": [], "voters": []}

def save_data(data):
    DATA_FILE.write_text(json.dumps(data, indent=2), encoding='utf-8')

@app.route('/')
def index():
    return render_template('landing.html')

@app.route('/admin')
def admin_home():
    return render_template('admin_choice.html')

@app.route('/voter')
def voter_home():
    return render_template('voter_choice.html')

# Admin auth
@app.route('/admin/register', methods=['GET','POST'])
def admin_register():
    data = load_data()
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        if any(a['username']==username for a in data.get('admins',[])):
            flash('Admin username already exists','danger')
        else:
            data.setdefault('admins',[]).append({'username': username, 'password': password})
            save_data(data)
            flash('Admin registered. Please login.','success')
            return redirect(url_for('admin_login'))
    return render_template('register.html', role='Admin', action_url=url_for('admin_register'))

@app.route('/admin/login', methods=['GET','POST'])
def admin_login():
    data = load_data()
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        for a in data.get('admins',[]):
            if a['username']==username and a['password']==password:
                session['user'] = username
                session['role'] = 'admin'
                flash('Logged in as admin','success')
                return redirect(url_for('admin_dashboard'))
        flash('Invalid credentials','danger')
    return render_template('login.html', role='Admin', action_url=url_for('admin_login'))

@app.route('/admin/dashboard')
def admin_dashboard():
    if session.get('role')!='admin':
        flash('Please login as admin','warning')
        return redirect(url_for('admin_login'))
    return render_template('dashboard.html', role='Admin', username=session.get('user'))

# Voter auth
@app.route('/voter/register', methods=['GET','POST'])
def voter_register():
    data = load_data()
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        if any(a['username']==username for a in data.get('voters',[])):
            flash('Voter username already exists','danger')
        else:
            data.setdefault('voters',[]).append({'username': username, 'password': password})
            save_data(data)
            flash('Voter registered. Please login.','success')
            return redirect(url_for('voter_login'))
    return render_template('register.html', role='Voter', action_url=url_for('voter_register'))

@app.route('/voter/login', methods=['GET','POST'])
def voter_login():
    data = load_data()
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        for a in data.get('voters',[]):
            if a['username']==username and a['password']==password:
                session['user'] = username
                session['role'] = 'voter'
                flash('Logged in as voter','success')
                return redirect(url_for('voter_dashboard'))
        flash('Invalid credentials','danger')
    return render_template('login.html', role='Voter', action_url=url_for('voter_login'))

@app.route('/voter/dashboard')
def voter_dashboard():
    if session.get('role')!='voter':
        flash('Please login as voter','warning')
        return redirect(url_for('voter_login'))
    return render_template('dashboard.html', role='Voter', username=session.get('user'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out','info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
