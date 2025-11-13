from flask import Flask, request, jsonify, render_template, render_template_string, redirect, url_for, session, send_file, abort, flash, get_flashed_messages
import hashlib, json, os, requests, time, csv, io, re
from functools import wraps
from datetime import datetime, timedelta
from blockchain import Blockchain
from werkzeug.security import generate_password_hash, check_password_hash

STORAGE = os.path.join(os.path.dirname(__file__), 'storage.json')

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET') or os.urandom(24)
bc = Blockchain(STORAGE)

# Session & auth hardening
SESSION_TIMEOUT_SECONDS = int(os.environ.get('SESSION_TIMEOUT', 1800))  # 30 minutes default
MAX_LOGIN_ATTEMPTS = int(os.environ.get('MAX_LOGIN_ATTEMPTS', 5))
LOCKOUT_SECONDS = int(os.environ.get('LOCKOUT_SECONDS', 300))  # 5 minutes default

# Ensure admin password is using werkzeug hash (migrate if still sha256)
def ensure_password_hash():
    admin = bc.data.get('admin', {})
    pw = admin.get('password_hash', '')
    # detect if it's a raw sha256 hex (length 64) then re-hash into werkzeug format
    if pw and len(pw) == 64 and pw.isalnum():
        # we can't recover original password; for demo we'll keep sha256 as valid by marking 'legacy'
        bc.data['admin']['password_hash_legacy'] = pw
        bc._save()

ensure_password_hash()

def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get('admin'):
            flash('Please login to access admin pages.', 'warning')
            return redirect(url_for('admin_login', next=request.path))
        # session timeout enforcement
        last = session.get('last_active')
        if last:
            try:
                last_dt = datetime.fromisoformat(last)
                if datetime.utcnow() - last_dt > timedelta(seconds=SESSION_TIMEOUT_SECONDS):
                    session.clear()
                    flash('Session expired. Please login again.', 'info')
                    return redirect(url_for('admin_login'))
            except Exception:
                # if parse fails, clear session to be safe
                session.clear()
                flash('Session invalid. Please login again.', 'info')
                return redirect(url_for('admin_login'))
        # update last active
        session['last_active'] = datetime.utcnow().isoformat()
        return fn(*args, **kwargs)
    return wrapper

INDEX_HTML = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Blockchain Voting - Enhanced</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  </head>
  <body class="bg-light">
    <div class="container py-4">
      <h1 class="mb-3">Blockchain Voting System — Enhanced</h1>
      <div class="row">
        <div class="col-md-6">
          <div class="card mb-3">
            <div class="card-body">
              <h5>Cast Vote</h5>
              <form method="post" action="/vote">
                <div class="mb-2"><input required name="voter_id" class="form-control" placeholder="Voter ID"></div>
                <div class="mb-2"><input required name="candidate" class="form-control" placeholder="Candidate"></div>
                <button class="btn btn-primary">Submit Vote</button>
              </form>
            </div>
          </div>
          <div class="mb-2">
            <a class="btn btn-info" href="/chain">View Public Blockchain</a>
            <a class="btn btn-secondary" href="/results">View Results</a>
            <a class="btn btn-outline-dark" href="/nodes">Manage Nodes</a>
          </div>
        </div>
        <div class="col-md-6">
          <div class="card mb-3">
            <div class="card-body">
              <h5>Admin</h5>
                                {% if 'admin' in session and session['admin'] %}
                <p>Logged in as <strong>{{ session.get('username') }}</strong></p>
                <a class="btn btn-warning mb-2" href="/admin/dashboard">Admin Dashboard</a><br>
                <form method="post" action="/close" onsubmit="return confirm('Close voting? This will finalize votes and reveal results.')">
                  <button class="btn btn-danger">Close Voting & Finalize</button>
                </form>
                <a class="btn btn-secondary mt-2" href="/logout">Logout</a>
              {% else %}
                                <a class="btn btn-success" href="/admin/login">Admin Login</a>
                                <a class="btn btn-outline-primary mt-2" href="/user/register">Register Voter</a>
                                <a class="btn btn-outline-success mt-2" href="/user/login">Voter Login</a>
              {% endif %}
            </div>
          </div>
        </div>
      </div>
    </div>
  </body>
</html>
"""

LOGIN_HTML = """<!doctype html><html><body class='p-3'><h3>Admin Login</h3>
<form method='post' action='/admin/login'>
<label>Username</label><input name='username' class='form-control mb-2'><label>Password</label><input name='password' type='password' class='form-control mb-2'><button class='btn btn-primary'>Login</button>
</form><p><a href='/'>Back</a></p></body></html>"""

DASH_HTML = """<!doctype html>
<html>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1'>
  <title>Admin Dashboard</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body class='bg-light p-3'>
  <div class='container'>
    <h2>Admin Dashboard</h2>
    <div class='row'>
      <div class='col-md-3'>
        <div class='card mb-3 p-2'><strong>Total Votes</strong><div id='total_votes'>{{ total_votes }}</div></div>
      </div>
      <div class='col-md-3'>
        <div class='card mb-3 p-2'><strong>Pending Votes</strong><div id='pending_votes'>{{ pending_votes }}</div></div>
      </div>
      <div class='col-md-3'>
        <div class='card mb-3 p-2'><strong>Voting Status</strong><div id='voting_status'>{{ voting_status }}</div></div>
      </div>
      <div class='col-md-3'>
        <div class='card mb-3 p-2'><strong>Blocks</strong><div id='block_count'>{{ block_count }}</div></div>
      </div>
    </div>

    <div class='card mb-3 p-3'>
      <h5>Candidate Chart</h5>
      <canvas id='candidateChart'></canvas>
    </div>

    <div class='row'>
      <div class='col-md-6'>
        <a class='btn btn-outline-primary' href='/admin/explorer'>Blockchain Explorer</a>
        <a class='btn btn-outline-success' href='/export/results.csv'>Download Results (.csv)</a>
        <a class='btn btn-outline-secondary' href='/export/blockchain.json'>Download Blockchain (.json)</a>
      </div>
      <div class='col-md-6 text-end'>
        <a class='btn btn-danger' href='/logout'>Logout</a>
      </div>
    </div>

    <hr>
    <h5>Change Password</h5>
    <form method='post' action='/admin/change_password'>
      <div class='mb-2'><input name='current_password' type='password' class='form-control' placeholder='Current password' required></div>
      <div class='mb-2'><input name='new_password' type='password' class='form-control' placeholder='New password' required></div>
      <button class='btn btn-warning'>Change Password</button>
    </form>

  </div>

<script>
const labels = {{ labels | safe }};
const data = {{ data | safe }};
const ctx = document.getElementById('candidateChart').getContext('2d');
new Chart(ctx, {
    type: 'bar',
    data: {
        labels: labels,
        datasets: [{
            label: 'Votes',
            data: data,
        }]
    },
    options: {}
});
</script>
</body>
</html>
"""

EXPLORER_HTML = """<!doctype html><html><body class='p-3'><h3>Blockchain Explorer</h3>
<form method='get' action='/admin/explorer'><input name='q' class='form-control mb-2' placeholder='Search candidate or block index'><button class='btn btn-primary mb-2'>Search</button></form>
<table class='table table-striped'><thead><tr><th>Index</th><th>Timestamp</th><th>Candidate</th><th>Hash</th><th>Proof</th></tr></thead><tbody>{% for b in blocks %}<tr><td>{{b.index}}</td><td>{{b.timestamp}}</td><td>{{b.candidate}}</td><td style='word-break:break-all'>{{b.hash}}</td><td>{{b.proof}}</td></tr>{% endfor %}</tbody></table>
<p><a href='/admin/dashboard'>Back</a></p></body></html>"""

NODES_HTML = """<!doctype html><html><body class='p-3'><h3>Node Management</h3>
<form method='post' action='/nodes/register'><input name='node_url' class='form-control mb-2' placeholder='http://127.0.0.1:5001'><button class='btn btn-primary'>Register Node</button></form>
<ul>{% for n in nodes %}<li>{{n}}</li>{% endfor %}</ul>
<form method='post' action='/nodes/resolve'><button class='btn btn-warning'>Resolve Consensus</button></form>
<p><a href='/admin/dashboard'>Back</a></p></body></html>"""

def hash_voter(voter_id):
    return hashlib.sha256(voter_id.strip().encode()).hexdigest()

@app.route('/')
def index():
    return render_template_string(INDEX_HTML)

@app.route('/vote', methods=['POST'])
def vote():
    # require logged-in voter
    if not session.get('voter_authenticated'):
        # redirect to voter login
        flash('You must be logged in to cast a vote.', 'warning')
        return redirect(url_for('user_login'))
    candidate = request.form.get('candidate', '').strip()
    if not candidate:
        return jsonify({'error': 'candidate required'}), 400
    try:
        vh = session.get('voter_hash')
        if not vh:
            return jsonify({'error': 'voter session invalid'}), 400
        vote = bc.add_vote(voter_hash=vh, candidate=candidate)
        return redirect(url_for('index'))
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# Voter user auth and registration
@app.route('/user/register', methods=['GET', 'POST'])
def user_register():
    if request.method == 'GET':
        return render_template('user_register.html')
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    voter_id = request.form.get('voter_id', '').strip()
    if not username or not password or not voter_id:
        flash('All fields are required.', 'danger')
        return redirect(url_for('user_register'))
    users = bc.data.get('users', [])
    if any(u['username'] == username for u in users):
        flash('Username already exists.', 'danger')
        return redirect(url_for('user_register'))
    voter_hash = hash_voter(voter_id)
    # ensure voter hasn't already been registered as voted
    # store user
    user = {
        'username': username,
        'password_hash': generate_password_hash(password),
        'voter_hash': voter_hash,
        'created_at': time.time()
    }
    bc.data.setdefault('users', []).append(user)
    bc._save()
    flash('Registration successful. Please login to vote.', 'success')
    return redirect(url_for('user_login'))

@app.route('/user/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'GET':
        return render_template('user_login.html')
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    users = bc.data.get('users', [])
    user = next((u for u in users if u['username'] == username), None)
    if not user:
        flash('Invalid credentials', 'danger')
        return redirect(url_for('user_login'))
    try:
        if check_password_hash(user.get('password_hash', ''), password):
            session['voter_authenticated'] = True
            session['voter_username'] = username
            session['voter_hash'] = user.get('voter_hash')
            session['last_active'] = datetime.utcnow().isoformat()
            flash('Logged in as voter', 'success')
            return redirect(url_for('index'))
    except Exception:
        pass
    flash('Invalid credentials', 'danger')
    return redirect(url_for('user_login'))

@app.route('/user/logout')
def user_logout():
    session_keys = ['voter_authenticated', 'voter_username', 'voter_hash']
    for k in session_keys:
        session.pop(k, None)
    flash('Logged out.', 'info')
    return redirect(url_for('index'))

# Admin can register other admins (super admin only)
@app.route('/admin/register', methods=['GET', 'POST'])
@require_admin
def admin_register():
    # Check if current admin is super admin
    if not session.get('is_super_admin'):
        flash('Only super admins can create new admin accounts.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'GET':
        return render_template('admin_register.html')

    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    is_super = request.form.get('is_super_admin') == 'on'

    if not username or not password or not email:
        flash('All fields required', 'danger')
        return redirect(url_for('admin_register'))
    
    # Validate email format
    if '@' not in email or '.' not in email:
        flash('Invalid email format', 'danger')
        return redirect(url_for('admin_register'))

    admins = bc.data.get('admins', [])
    if any(a['username'] == username for a in admins):
        flash('Username already exists', 'danger')
        return redirect(url_for('admin_register'))

    # Validate email format with regex
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        flash('Invalid email format', 'danger')
        return redirect(url_for('admin_register'))

    # Check if email already exists
    if any(a.get('email') == email for a in admins):
        flash('Email already exists', 'danger')
        return redirect(url_for('admin_register'))

    admin = {
        'username': username,
        'email': email,
        'password_hash': generate_password_hash(password),
        'is_super_admin': is_super,
        'created_at': time.time()
    }
    bc.data.setdefault('admins', []).append(admin)
    bc._save()
    flash('Admin account created successfully', 'success')
    return redirect(url_for('admin_dashboard'))

# Admin can register voters
@app.route('/admin/register_user', methods=['GET', 'POST'])
@require_admin
def admin_register_user():
    if request.method == 'GET':
        return render_template('admin_register_user.html')
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    voter_id = request.form.get('voter_id', '').strip()
    if not username or not password or not voter_id:
        flash('All fields required', 'danger')
        return redirect(url_for('admin_register_user'))
    users = bc.data.get('users', [])
    if any(u['username'] == username for u in users):
        flash('Username already exists', 'danger')
        return redirect(url_for('admin_register_user'))
    user = {
        'username': username,
        'password_hash': generate_password_hash(password),
        'voter_hash': hash_voter(voter_id),
        'created_at': time.time()
    }
    bc.data.setdefault('users', []).append(user)
    bc._save()
    flash('Voter account created', 'success')
    return redirect(url_for('admin_dashboard'))

# Admin auth
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'GET':
        # render a proper template with flash messaging
        return render_template('login.html')
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    admins = bc.data.get('admins', [])
    admin = next((a for a in admins if a['username'] == username), None)
    if not admin:
        flash('Invalid credentials', 'danger')
        return redirect(url_for('admin_login'))
    stored_hash = admin.get('password_hash')
    # support legacy sha256 flag
    if admin.get('password_hash_legacy'):
        legacy = admin.get('password_hash_legacy')
    else:
        legacy = None
    # check werkzeug hash first
    try:
        if stored_hash and (stored_hash.startswith('pbkdf2:') or stored_hash.startswith('argon2:')):
            valid = check_password_hash(stored_hash, password)
        else:
            valid = False
    except Exception:
        valid = False
    # fallback: if legacy sha256 exists, compare
    if not valid and legacy:
        if hashlib.sha256(password.encode()).hexdigest() == legacy:
            valid = True
            # migrate to werkzeug hash
            newh = generate_password_hash(password)
            bc.data['admin']['password_hash'] = newh
            del bc.data['admin']['password_hash_legacy']
            bc._save()
    # login attempt tracking and lockout
    now_ts = int(time.time())
    attempts = admin.get('login_attempts', 0)
    lockout_until = admin.get('lockout_until', 0)
    if lockout_until and now_ts < lockout_until:
        flash('Too many failed attempts. Try again later.', 'danger')
        return redirect(url_for('admin_login'))

    admins = bc.data.get('admins', [])
    admin = next((a for a in admins if a['username'] == username), None)
    if admin and valid:
        session['admin'] = True
        session['username'] = username
        session['is_super_admin'] = admin.get('is_super_admin', False)
        session['last_active'] = datetime.utcnow().isoformat()
        # reset attempts
        admin['login_attempts'] = 0
        admin.pop('lockout_until', None)
        bc._save()
        next_url = request.args.get('next') or url_for('admin_dashboard')
        flash('Login successful', 'success')
        return redirect(next_url)
    # invalid
    attempts += 1
    bc.data['admin']['login_attempts'] = attempts
    if attempts >= MAX_LOGIN_ATTEMPTS:
        bc.data['admin']['lockout_until'] = now_ts + LOCKOUT_SECONDS
        flash(f'Too many failed attempts. Locked for {LOCKOUT_SECONDS} seconds.', 'danger')
    else:
        flash('Invalid credentials', 'danger')
    bc._save()
    return redirect(url_for('admin_login'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get('admin'):
            flash('Please login to access admin pages.', 'warning')
            return redirect(url_for('admin_login', next=request.path))
        # session timeout enforcement
        last = session.get('last_active')
        if last:
            try:
                last_dt = datetime.fromisoformat(last)
                if datetime.utcnow() - last_dt > timedelta(seconds=SESSION_TIMEOUT_SECONDS):
                    session.clear()
                    flash('Session expired. Please login again.', 'info')
                    return redirect(url_for('admin_login'))
            except Exception:
                # if parse fails, clear session to be safe
                session.clear()
                flash('Session invalid. Please login again.', 'info')
                return redirect(url_for('admin_login'))
        # update last active
        session['last_active'] = datetime.utcnow().isoformat()
        return fn(*args, **kwargs)
    return wrapper

# Admin dashboard
@app.route('/admin/dashboard')
@require_admin
def admin_dashboard():
    total_votes = len([b for b in bc.data['chain'] if b.get('vote')])
    pending_votes = len(bc.data.get('pending_votes', []))
    voting_status = 'Open' if bc.data.get('voting_open', True) else 'Closed'
    block_count = len(bc.data.get('chain', []))
    # results for chart
    try:
        results = bc.get_results() if not bc.data.get('voting_open') else {}
    except Exception:
        results = {}
    # if voting still open, create counts from chain blocks only
    counts = {}
    for b in bc.data.get('chain', []):
        if b.get('vote') and b['vote'].get('candidate'):
            counts[b['vote']['candidate']] = counts.get(b['vote']['candidate'], 0) + 1
    labels = list(counts.keys())
    data_vals = [counts[k] for k in labels]
    # render template (keeps Chart.js usage)
    return render_template('admin_dashboard.html', total_votes=total_votes, pending_votes=pending_votes,
                                  voting_status=voting_status, block_count=block_count,
                                  labels=json.dumps(labels), data=json.dumps(data_vals),
                                  labels_raw=labels, data_raw=data_vals, labelsjs=json.dumps(labels),
                                  datajs=json.dumps(data_vals), labels_display=labels, data_display=data_vals)

@app.route('/admin/change_password', methods=['POST'])
@require_admin
def change_password():
    current = request.form.get('current_password', '')
    new = request.form.get('new_password', '')
    if not current or not new:
        return 'Both fields required', 400
    stored = bc.data.get('admin', {})
    # verify current
    valid = False
    stored_hash = stored.get('password_hash')
    legacy = stored.get('password_hash_legacy')
    try:
        if stored_hash and (stored_hash.startswith('pbkdf2:') or stored_hash.startswith('argon2:')):
            valid = check_password_hash(stored_hash, current)
    except Exception:
        valid = False
    if not valid and legacy:
        if hashlib.sha256(current.encode()).hexdigest() == legacy:
            valid = True
    if not valid:
        return 'Current password incorrect', 403
    # set new password with werkzeug
    bc.data['admin']['password_hash'] = generate_password_hash(new)
    if 'password_hash_legacy' in bc.data['admin']:
        del bc.data['admin']['password_hash_legacy']
    bc._save()
    flash('Password changed successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/close', methods=['POST'])
@require_admin
def close_voting():
    # Only super admins can close voting
    if not session.get('is_super_admin'):
        flash('Only super admins can close voting.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    result = bc.close_voting_and_finalize(difficulty=3)
    # broadcast chain to peers (best-effort)
    for node in bc.data.get('nodes', []):
        try:
            url = node.rstrip('/') + '/receive_chain'
            requests.post(url, json={'chain': bc.data['chain']}, timeout=2)
        except Exception:
            pass
    return jsonify({'status': result['status'], 'mined_blocks': len(result.get('mined_blocks', []))})

@app.route('/results', methods=['GET'])
def results():
    try:
        counts = bc.get_results()
        if not counts:
            html = '<p>No votes recorded.</p>'
        else:
            rows = ''.join(f'<li>{c}: {v}</li>' for c, v in counts.items())
            html = f'<ul>{rows}</ul>'
        return render_template_string('<h3>Results</h3>' + html + '<p><a href="/">Back</a></p>')
    except Exception as e:
        return render_template_string(f'<h3>Results</h3><p><strong>Unavailable:</strong> {e}</p><p><a href="/">Back</a></p>')

@app.route('/chain', methods=['GET'])
def chain():
    public = bc.get_chain_public()
    return jsonify({'length': len(public), 'chain': public})

# Node management
@app.route('/nodes', methods=['GET'])
def nodes_page():
    return render_template_string(NODES_HTML, nodes=bc.data.get('nodes', []))

@app.route('/nodes/register', methods=['POST'])
def register_node():
    node_url = request.form.get('node_url') or request.json.get('node_url')
    if not node_url:
        return 'node_url required', 400
    nodes = bc.register_node(node_url)
    return redirect(url_for('nodes_page'))

@app.route('/nodes/resolve', methods=['POST'])
def resolve_nodes():
    replaced = False
    checked = 0
    for node in bc.data.get('nodes', []):
        try:
            checked += 1
            resp = requests.get(node.rstrip('/') + '/full_chain', timeout=2)
            data = resp.json()
            remote_chain = data.get('chain')
            if remote_chain and len(remote_chain) > len(bc.data['chain']):
                if bc.replace_chain(remote_chain):
                    replaced = True
        except Exception:
            pass
    return jsonify({'replaced': replaced, 'nodes_checked': checked})

@app.route('/receive_chain', methods=['POST'])
def receive_chain():
    incoming = request.json.get('chain')
    if not incoming:
        return 'chain required', 400
    if bc.replace_chain(incoming):
        return 'replaced', 200
    return 'not replaced', 200

@app.route('/full_chain', methods=['GET'])
def full_chain():
    return jsonify({'length': len(bc.data['chain']), 'chain': bc.data['chain']})

# Blockchain explorer (admin)
@app.route('/admin/explorer', methods=['GET'])
@require_admin
def admin_explorer():
    # Only super admins can view the explorer
    if not session.get('is_super_admin'):
        flash('Only super admins can access the blockchain explorer.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    q = request.args.get('q', '').strip()
    blocks = []
    for b in bc.data.get('chain', []):
        blocks.append({
            'index': b['index'],
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(b['timestamp'])),
            'candidate': b['vote']['candidate'] if b['vote'] else None,
            'hash': b['hash'],
            'proof': b.get('proof')
        })
    if q:
        # filter by candidate substring or index integer
        filtered = []
        for b in blocks:
            if q.isdigit() and int(q) == b['index']:
                filtered.append(b)
            elif b['candidate'] and q.lower() in b['candidate'].lower():
                filtered.append(b)
        blocks = filtered
    return render_template_string(EXPLORER_HTML, blocks=blocks)

# Export endpoints
@app.route('/export/results.csv', methods=['GET'])
@require_admin
def export_results_csv():
    # produce CSV of candidate,count
    try:
        counts = bc.get_results()
    except Exception:
        counts = {}
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['candidate','votes'])
    for k,v in counts.items():
        cw.writerow([k,v])
    mem = io.BytesIO()
    mem.write(si.getvalue().encode())
    mem.seek(0)
    return send_file(mem, mimetype='text/csv', as_attachment=True, download_name='results.csv')

@app.route('/export/blockchain.json', methods=['GET'])
@require_admin
def export_blockchain_json():
    mem = io.BytesIO()
    mem.write(json.dumps(bc.data['chain'], indent=2).encode())
    mem.seek(0)
    return send_file(mem, mimetype='application/json', as_attachment=True, download_name='blockchain.json')

# Public chain view
@app.route('/public_chain', methods=['GET'])
def public_chain_view():
    return jsonify({'length': len(bc.data['chain']), 'chain': bc.get_chain_public()})

# Candidate management routes
@app.route('/admin/candidates', methods=['GET'])
@require_admin
def manage_candidates():
    if not session.get('is_super_admin'):
        flash('Only super admins can manage candidates.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    candidates = bc.data.get('candidates', [])
    return render_template('manage_candidates.html', candidates=candidates)

@app.route('/admin/candidates/add', methods=['POST'])
@require_admin
def add_candidate():
    if not session.get('is_super_admin'):
        flash('Only super admins can manage candidates.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    candidate_id = request.form.get('candidate_id', '').strip()
    name = request.form.get('name', '').strip()
    party = request.form.get('party', '').strip()

    if not candidate_id or not name or not party:
        flash('All fields are required.', 'danger')
        return redirect(url_for('manage_candidates'))

    candidates = bc.data.get('candidates', [])
    
    # Check if candidate ID already exists
    if any(c['id'] == candidate_id for c in candidates):
        flash('Candidate ID already exists.', 'danger')
        return redirect(url_for('manage_candidates'))

    # Create new candidate
    candidate = {
        'id': candidate_id,
        'name': name,
        'party': party,
        'created_at': time.time()
    }

    bc.data.setdefault('candidates', []).append(candidate)
    bc._save()

    flash('Candidate added successfully.', 'success')
    return redirect(url_for('manage_candidates'))

@app.route('/admin/candidates/edit/<candidate_id>', methods=['POST'])
@require_admin
def edit_candidate(candidate_id):
    if not session.get('is_super_admin'):
        flash('Only super admins can manage candidates.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    name = request.form.get('name', '').strip()
    party = request.form.get('party', '').strip()

    if not name or not party:
        flash('All fields are required.', 'danger')
        return redirect(url_for('manage_candidates'))

    candidates = bc.data.get('candidates', [])
    candidate = next((c for c in candidates if c['id'] == candidate_id), None)

    if not candidate:
        flash('Candidate not found.', 'danger')
        return redirect(url_for('manage_candidates'))

    # Update candidate
    candidate['name'] = name
    candidate['party'] = party
    candidate['updated_at'] = time.time()
    bc._save()

    flash('Candidate updated successfully.', 'success')
    return redirect(url_for('manage_candidates'))

@app.route('/admin/candidates/delete/<candidate_id>', methods=['POST'])
@require_admin
def delete_candidate(candidate_id):
    if not session.get('is_super_admin'):
        flash('Only super admins can manage candidates.', 'danger')
        return redirect(url_for('admin_dashboard'))

    candidates = bc.data.get('candidates', [])
    candidate = next((c for c in candidates if c['id'] == candidate_id), None)

    if not candidate:
        flash('Candidate not found.', 'danger')
        return redirect(url_for('manage_candidates'))

    # Check if votes exist for this candidate
    chain = bc.data.get('chain', [])
    votes_exist = any(b.get('vote', {}).get('candidate') == candidate_id for b in chain)

    if votes_exist:
        flash('Cannot delete candidate with existing votes.', 'danger')
        return redirect(url_for('manage_candidates'))

    # Remove candidate
    bc.data['candidates'] = [c for c in candidates if c['id'] != candidate_id]
    bc._save()

    flash('Candidate deleted successfully.', 'success')
    return redirect(url_for('manage_candidates'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)
