from app import app, bc, hash_password
from pathlib import Path
import json

# Use Flask test_client to simulate web flow
client = app.test_client()

def pretty_print(resp):
    print('STATUS', resp.status_code)
    print(resp.get_data(as_text=True)[:1000])

# Ensure clean-ish starting point (will not delete storage, just print current state)
print('Current election_started:', bc.data.get('election_started'))
print('Current voting_open:', bc.data.get('voting_open'))
print('Candidates before:', bc.get_candidates())

# Login as admin (default admin exists)
resp = client.post('/admin/login', data={'username':'admin','password':'adminpass'}, follow_redirects=True)
print('\n--- Admin login ---')
pretty_print(resp)

# Add a candidate
resp = client.post('/admin/add_candidate', data={'name':'Alice','party':'Blue'}, follow_redirects=True)
print('\n--- Add candidate ---')
pretty_print(resp)

# Get candidates list
print('\nCandidates after add:', bc.get_candidates())

# Start election
resp = client.post('/admin/manage_election', data={'action':'start'}, follow_redirects=True)
print('\n--- Start election ---')
pretty_print(resp)
print('After start election_started:', bc.data.get('election_started'), 'voting_open:', bc.data.get('voting_open'))

# Register a voter
resp = client.post('/voter/register', data={'username':'voter1','password':'vpass'}, follow_redirects=True)
print('\n--- Voter register ---')
pretty_print(resp)

# Voter login
resp = client.post('/voter/login', data={'username':'voter1','password':'vpass'}, follow_redirects=True)
print('\n--- Voter login ---')
pretty_print(resp)

# Get candidate id to vote for
candidates = bc.get_candidates()
if not candidates:
    print('No candidates to vote for')
else:
    candidate_id = candidates[0]['id']
    # Cast vote
    resp = client.post('/voter/dashboard', data={'candidate_id':candidate_id}, follow_redirects=True)
    print('\n--- Cast vote ---')
    pretty_print(resp)
    print('voters list after vote:', bc.data.get('voters'))

# Admin close election
resp = client.post('/admin/manage_election', data={'action':'close'}, follow_redirects=True)
print('\n--- Close election ---')
pretty_print(resp)
print('After close election_started:', bc.data.get('election_started'), 'voting_open:', bc.data.get('voting_open'))

# Admin view results
resp = client.get('/admin/view_results')
print('\n--- View results ---')
pretty_print(resp)

# Admin download results
resp = client.get('/admin/download_results')
print('\n--- Download results (first 300 chars) ---')
print(resp.status_code)
print(resp.get_data(as_text=True)[:300])

print('\nTest flow completed')
