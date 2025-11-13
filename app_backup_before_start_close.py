
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from werkzeug.security import check_password_hash
import csv
from io import StringIO
from pathlib import Path
import hashlib, os, json, time
from blockchain import Blockchain

app = Flask(__name__)
app.secret_key = 'replace-this-with-a-secure-key'

STORAGE = Path(__file__).parent / "storage.json"
# instantiate blockchain
bc = Blockchain(str(STORAGE))

def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def ensure_bc_users_synced():
    # Ensure bc.data has 'users' and 'admins' list updated from storage if necessary
    # This function keeps simple app registration and blockchain storage in sync.
    try:
        with open(STORAGE, 'r') as f:
            data = json.load(f)
    except Exception:
        data = {}
    # ensure users and admins keys exist
    data.setdefault('users', [])
    data.setdefault('admins', bc.data.get('admins', []))
    # write back minimal if changed
    with open(STORAGE, 'w') as f:
        json.dump(bc.data, f, indent=2)

@app.route('/')
def index():
    return render_template('landing.html')

@app.route('/admin')
def admin_home():
    return render_template('admin_choice.html')

@app.route('/voter')
def voter_home():
    return render_template('voter_choice.html')

# Admin register/login integrated with blockchain admins
@app.route('/admin/register', methods=['GET','POST'])
def admin_register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        # check exists
        for a in bc.data.get('admins', []):
            if a['username'] == username:
                flash('Admin username already exists','danger')
                return redirect(url_for('admin_register'))
        admin_entry = {
            'username': username,
            'password_hash': hash_password(password),
            'is_super_admin': False,
            'created_at': time.time()
        }
        bc.data.setdefault('admins', []).append(admin_entry)
        bc._save()
        flash('Admin registered. Please login.','success')
        return redirect(url_for('admin_login'))
    return render_template('register.html', role='Admin', action_url=url_for('admin_register'))

@app.route('/admin/login', methods=['GET','POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        ph = hash_password(password)
        for a in bc.data.get('admins', []):
            if a.get('username') != username:
                continue
            stored = a.get('password_hash','')
            # support hashed passwords created by werkzeug (e.g. scrypt/pbkdf2) or legacy sha256
            try:
                if stored and (stored.startswith('scrypt:') or ':' in stored):
                    ok = check_password_hash(stored, password)
                else:
                    ok = (stored == ph)
            except Exception:
                ok = (stored == ph)
            if ok:
                session['user'] = username
                session['role'] = 'admin'
                flash('Logged in as admin','success')
                return redirect(url_for('admin_dashboard'))
        flash('Invalid credentials','danger')
    return render_template('login.html', role='Admin', action_url=url_for('admin_login'))

@app.route('/admin/dashboard')
def admin_dashboard():
    if session.get('role') != 'admin':
        flash('Please login as admin', 'warning')
        return redirect(url_for('admin_login'))
    
    candidates = bc.get_candidates()
    voting_open = bc.data.get('voting_open', False)
    election_started = bc.data.get('election_started', False)
    
    return render_template('admin_dashboard.html', 
                         candidates=candidates,
                         voting_open=voting_open,
                         election_started=election_started,
                         username=session.get('user'))

@app.route('/admin/add_candidate', methods=['POST'])
def admin_add_candidate():
    if session.get('role') != 'admin':
        flash('Please login as admin', 'warning')
        return redirect(url_for('admin_login'))
    
    name = request.form.get('name', '').strip()
    party = request.form.get('party', '').strip()
    
    if not name or not party:
        flash('Both name and party are required', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    try:
        candidate = bc.add_candidate(name, party)
        flash(f'Candidate {name} added', 'success')
    except Exception as e:
        flash(str(e), 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_candidate/<candidate_id>', methods=['POST'])
def admin_delete_candidate(candidate_id):
    if session.get('role') != 'admin':
        flash('Please login as admin', 'warning')
        return redirect(url_for('admin_login'))
    
    if bc.delete_candidate(candidate_id):
        flash('Candidate removed successfully', 'success')
    else:
        flash('Failed to remove candidate', 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/start_election', methods=['POST'])
def admin_start_election():
    if session.get('role') != 'admin':
        flash('Please login as admin', 'warning')
        return redirect(url_for('admin_login'))
    
    if not bc.get_candidates():
        flash('Cannot start election without candidates', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    try:
        bc.start_election()
        flash('Election started successfully', 'success')
    except ValueError as e:
        flash(str(e), 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/manage_election', methods=['POST'])
def admin_manage_election():
    if session.get('role') != 'admin':
        flash('Please login as admin', 'warning')
        return redirect(url_for('admin_login'))
    
    action = request.form.get('action')
    
    try:
        if action == 'start':
            if not bc.get_candidates():
                flash('Cannot start election without candidates', 'danger')
            else:
                bc.start_election()
                flash('Election started successfully', 'success')
        elif action == 'close':
            result = bc.close_election()
            flash(f"Election closed. {len(result.get('mined_blocks', []))} votes processed.", 'success')
        else:
            flash('Invalid action', 'danger')
    except ValueError as e:
        flash(str(e), 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/view_results')
def admin_view_results():
    if session.get('role') != 'admin':
        flash('Please login as admin', 'warning')
        return redirect(url_for('admin_login'))
    
    if bc.data.get('voting_open', False):
        flash('Cannot view results while voting is open', 'warning')
        return redirect(url_for('admin_dashboard'))
    
    try:
        vote_counts = bc.get_results()
        results = []
        for candidate in bc.get_candidates():
            results.append({
                'name': candidate['name'],
                'party_name': candidate['party_name'],
                'votes': vote_counts.get(candidate['name'], 0)
            })
        return render_template('download_results.html', results=results)
    except Exception as e:
        flash(str(e), 'danger')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/download_results')
def admin_download_results():
    if session.get('role') != 'admin':
        flash('Please login as admin', 'warning')
        return redirect(url_for('admin_login'))
    
    if bc.data.get('voting_open', False):
        flash('Cannot download results while voting is open', 'warning')
        return redirect(url_for('admin_dashboard'))
    
    try:
        vote_counts = bc.get_results()
        si = StringIO()
        cw = csv.writer(si)
        cw.writerow(['Candidate Name', 'Party', 'Votes'])
        
        for candidate in bc.get_candidates():
            cw.writerow([
                candidate['name'],
                candidate['party_name'],
                vote_counts.get(candidate['name'], 0)
            ])
        
        output = si.getvalue()
        si.close()
        
        return send_file(
            StringIO(output),
            mimetype='text/csv',
            as_attachment=True,
            download_name='election_results.csv'
        )
    except Exception as e:
        flash(str(e), 'danger')
        return redirect(url_for('admin_dashboard'))

# Voter register/login integrated with blockchain users
@app.route('/voter/register', methods=['GET','POST'])
def voter_register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        # ensure not duplicate in bc.data['users']
        for u in bc.data.get('users', []):
            if u.get('username')==username:
                flash('Voter username already exists','danger')
                return redirect(url_for('voter_register'))
        user_entry = {
            'username': username,
            'password_hash': hash_password(password),
            'created_at': time.time()
        }
        bc.data.setdefault('users', []).append(user_entry)
        bc._save()
        flash('Voter registered. Please login.','success')
        return redirect(url_for('voter_login'))
    return render_template('register.html', role='Voter', action_url=url_for('voter_register'))

@app.route('/voter/login', methods=['GET','POST'])
def voter_login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        ph = hash_password(password)
        for u in bc.data.get('users', []):
            if u.get('username') != username:
                continue
            stored = u.get('password_hash', '')
            try:
                if stored and (stored.startswith('scrypt:') or ':' in stored):
                    ok = check_password_hash(stored, password)
                else:
                    ok = (stored == ph)
            except Exception:
                ok = (stored == ph)
            if ok:
                session['user'] = username
                session['role'] = 'voter'
                flash('Logged in as voter','success')
                return redirect(url_for('voter_dashboard'))
        flash('Invalid credentials','danger')
    return render_template('login.html', role='Voter', action_url=url_for('voter_login'))

@app.route('/voter/dashboard', methods=['GET','POST'])
def voter_dashboard():
    if session.get('role') != 'voter':
        flash('Please login as voter', 'warning')
        return redirect(url_for('voter_login'))

    voter_hash = hashlib.sha256(session.get('user').encode()).hexdigest()
    election_started = bc.data.get('election_started', False)
    voting_open = bc.data.get('voting_open', False)
    voted = voter_hash in bc.data.get('voters', [])
    candidates = bc.get_candidates()

    # handle voting
    if request.method == 'POST':
        if not election_started:
            flash('The election has not started yet.', 'warning')
        elif not voting_open:
            flash('Voting is currently closed.', 'warning')
        elif voted:
            flash('You have already voted.', 'warning')
        else:
            candidate_id = request.form.get('candidate_id')
            if not candidate_id:
                flash('Please select a candidate', 'warning')
            else:
                try:
                    vote = bc.add_vote(voter_hash, candidate_id)
                    # mine immediately for demo (so vote is visible)
                    bc.mine_pending_votes()
                    flash(f"Vote cast successfully! Token: {vote.get('token')}", 'success')
                except Exception as e:
                    flash(str(e), 'danger')
        return redirect(url_for('voter_dashboard'))

    return render_template('voter_dashboard.html', 
                         candidates=candidates,
                         voted=voted,
                         username=session.get('user'),
                         voting_open=voting_open,
                         election_started=election_started)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out','info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
