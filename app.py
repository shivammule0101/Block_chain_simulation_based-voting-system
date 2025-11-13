from flask import Flask, render_template, request, redirect, url_for, flash, session
import hashlib
from pathlib import Path
from blockchain import Blockchain

app = Flask(__name__)
app.secret_key = 'secure-key'

STORAGE = Path(__file__).parent / "storage.json"

def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()


# ------------------ MAIN PAGE ------------------
@app.route('/')
def index():
    return render_template('landing.html')


# ------------------ ADMIN REGISTER ------------------
@app.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    """
    ✅ Fix: This route was missing before — now added to prevent BuildError.
    Allows registering new admin accounts.
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        bc = Blockchain(str(STORAGE))

        # Prevent duplicates
        for a in bc.data.get('admins', []):
            if a['username'] == username:
                flash('Admin already exists', 'danger')
                return redirect(url_for('admin_register'))

        bc.data['admins'].append({
            'username': username,
            'password_hash': hash_password(password)
        })
        bc._save()
        flash('Admin registered successfully!', 'success')
        return redirect(url_for('admin_login'))

    return render_template('register.html', role='Admin', action_url=url_for('admin_register'))


# ------------------ ADMIN LOGIN ------------------
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        bc = Blockchain(str(STORAGE))
        for a in bc.data.get('admins', []):
            if a['username'] == username and a['password_hash'] == hash_password(password):
                session['user'] = username
                session['role'] = 'admin'
                flash('Welcome Admin', 'success')
                return redirect(url_for('admin_home'))

        flash('Invalid credentials', 'danger')
    return render_template('login.html', role='Admin', action_url=url_for('admin_login'))


# ------------------ ADMIN DASHBOARD ------------------
@app.route('/admin', methods=['GET'])
def admin_home():
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('admin_login'))

    bc = Blockchain(str(STORAGE))
    candidates = bc.get_candidates()
    voting_open = bc.data.get('voting_open', False)

    return render_template(
        'admin_dashboard.html',
        candidates=candidates,
        voting_open=voting_open,
        username=session.get('user')
    )


# ------------------ ADMIN ACTIONS ------------------
@app.route('/admin/add_candidate', methods=['POST'])
def add_candidate():
    if session.get('role') != 'admin':
        return redirect(url_for('admin_login'))

    bc = Blockchain(str(STORAGE))
    name = request.form['name']
    party = request.form['party']
    bc.add_candidate(name, party)
    flash(f"Candidate {name} added successfully!", 'success')
    return redirect(url_for('admin_home'))



@app.route('/admin/start_election', methods=['POST'])
def start_election():
    if session.get('role') != 'admin':
        return redirect(url_for('admin_login'))

    bc = Blockchain(str(STORAGE))
    # mark both voting_open and election_started for compatibility with templates
    bc.data['voting_open'] = True
    bc.data['election_started'] = True
    bc._save()
    flash('Election started! Voters can now vote.', 'success')
    return redirect(url_for('admin_home'))



@app.route('/admin/close_election', methods=['POST'])
def close_election():
    if session.get('role') != 'admin':
        return redirect(url_for('admin_login'))

    bc = Blockchain(str(STORAGE))
    bc.data['voting_open'] = False
    bc.data['election_started'] = False
    # finalize votes if needed
    try:
        bc.close_voting_and_finalize()
    except Exception:
        pass
    bc._save()
    flash('Election closed successfully.', 'info')
    return redirect(url_for('admin_home'))


# ------------------ VOTER AUTH ------------------
@app.route('/voter/register', methods=['GET', 'POST'])
def voter_register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        bc = Blockchain(str(STORAGE))
        for u in bc.data.get('users', []):
            if u['username'] == username:
                flash('Voter already registered', 'danger')
                return redirect(url_for('voter_register'))

        bc.data['users'].append({
            'username': username,
            'password_hash': hash_password(password)
        })
        bc._save()
        flash('Voter registered successfully!', 'success')
        return redirect(url_for('voter_login'))

    return render_template('register.html', role='Voter', action_url=url_for('voter_register'))


@app.route('/voter/login', methods=['GET', 'POST'])
def voter_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        bc = Blockchain(str(STORAGE))
        for v in bc.data.get('users', []):
            if v['username'] == username and v['password_hash'] == hash_password(password):
                session['user'] = username
                session['role'] = 'voter'
                flash('Welcome Voter', 'success')
                return redirect(url_for('voter_dashboard'))

        flash('Invalid credentials', 'danger')

    return render_template('login.html', role='Voter', action_url=url_for('voter_login'))


# ------------------ VOTER DASHBOARD ------------------
@app.route('/voter/dashboard', methods=['GET', 'POST'])
def voter_dashboard():
    if session.get('role') != 'voter':
        return redirect(url_for('voter_login'))

    bc_live = Blockchain(str(STORAGE))
    voting_open = bc_live.data.get('voting_open', False)
    election_started = bc_live.data.get('election_started', False)
    candidates = bc_live.get_candidates()
    voter_hash = hashlib.sha256(session['user'].encode()).hexdigest()
    voted = voter_hash in bc_live.data.get('voters', [])

    if not voting_open:
        flash('Election not started yet. Please wait for admin.', 'info')

    if request.method == 'POST' and voting_open and not voted:
        candidate_id = request.form['candidate_id']
        try:
            vote = bc_live.add_vote(voter_hash, candidate_id)
            bc_live.mine_pending_votes()
            flash(f"Vote successfully cast for {vote['candidate']}", 'success')
        except Exception as e:
            flash(str(e), 'danger')
        return redirect(url_for('voter_dashboard'))

    return render_template(
        'voter_dashboard.html',
        candidates=candidates,
        voting_open=voting_open,
        election_started=election_started,
        username=session['user'],
        voted=voted
    )


# ------------------ LOGOUT ------------------
@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'info')
    return redirect(url_for('index'))




# ------------------ ELECTION HELPERS ------------------
import json
def tally_votes(bc):
    # Count votes from the chain's blocks where 'vote' is not None
    counts = {}
    for block in bc.data.get('chain', []):
        vote = block.get('vote')
        if vote and isinstance(vote, dict):
            cid = vote.get('candidate_id')
            if cid:
                counts[cid] = counts.get(cid, 0) + 1
    # map candidate ids to names
    results = []
    id_to_name = {c['id']: c.get('name', c.get('id')) for c in bc.data.get('candidates', [])}
    for cid, cnt in counts.items():
        results.append({
            'id': cid,
            'name': id_to_name.get(cid, cid),
            'votes': cnt
        })
    # include candidates with zero votes
    for c in bc.data.get('candidates', []):
        if not any(r['id'] == c['id'] for r in results):
            results.append({'id': c['id'], 'name': c.get('name',''), 'votes': 0})
    # sort descending
    results.sort(key=lambda x: x['votes'], reverse=True)
    return results

@app.route('/admin/start_election', methods=['POST'])
def admin_start_election():

    if session.get('role') != 'admin':
        return redirect(url_for('admin_login'))
    bc = Blockchain(str(STORAGE))
    bc.data['voting_open'] = True
    bc.data['election_started'] = True
    # clear previous results if any
    if 'results' in bc.data:
        del bc.data['results']
    bc._save()
    flash('Election started.', 'success')
    return redirect(url_for('admin_home'))

@app.route('/admin/end_election', methods=['POST'])
def end_election():
    if session.get('role') != 'admin':
        return redirect(url_for('admin_login'))
    bc = Blockchain(str(STORAGE))
    # close voting and mine pending votes if any
    try:
        bc.close_voting_and_finalize()
    except Exception:
        pass
    # tally votes and store results
    results = tally_votes(bc)
    bc.data['results'] = results
    # delete all candidates after storing results
    bc.data['candidates'] = []
    bc.data['voting_open'] = False
    bc.data['election_started'] = False
    bc._save()
    flash('Election ended and results computed.', 'info')
    return redirect(url_for('admin_home'))

@app.route('/results')
def results():
    bc = Blockchain(str(STORAGE))
    results = bc.data.get('results', [])
    return render_template('results.html', results=results)


if __name__ == '__main__':
    app.run(debug=True)
