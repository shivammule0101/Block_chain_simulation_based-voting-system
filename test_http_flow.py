import requests
from urllib.parse import urljoin

BASE = 'http://127.0.0.1:5000'

s = requests.Session()

def show(resp):
    print(resp.status_code)
    print(resp.text[:800])

# Admin login
r = s.post(urljoin(BASE,'/admin/login'), data={'username':'admin','password':'adminpass'})
print('\n--- admin login ---')
show(r)

# Add candidate
r = s.post(urljoin(BASE,'/admin/add_candidate'), data={'name':'Bob','party':'Green'})
print('\n--- add candidate ---')
show(r)

# Start election
r = s.post(urljoin(BASE,'/admin/manage_election'), data={'action':'start'})
print('\n--- start election ---')
show(r)

# Voter register
r = s.post(urljoin(BASE,'/voter/register'), data={'username':'voter_http','password':'vpass'})
print('\n--- voter register ---')
show(r)

# Voter login
r = s.post(urljoin(BASE,'/voter/login'), data={'username':'voter_http','password':'vpass'})
print('\n--- voter login ---')
show(r)

# Get candidates page to find candidate id (simple parse)
r = s.get(urljoin(BASE,'/voter/dashboard'))
print('\n--- voter dashboard GET ---')
# naive parsing: look for value="<uuid>"
import re
m = re.search(r'value="([0-9a-fA-F\-]{36})"', r.text)
if m:
    candidate_id = m.group(1)
    print('found candidate id:', candidate_id)
    # cast vote
    r = s.post(urljoin(BASE,'/voter/dashboard'), data={'candidate_id':candidate_id})
    print('\n--- cast vote POST ---')
    show(r)
else:
    print('candidate id not found')

# Admin close election
r = s.post(urljoin(BASE,'/admin/manage_election'), data={'action':'close'})
print('\n--- close election ---')
show(r)

# Admin view results
r = s.get(urljoin(BASE,'/admin/view_results'))
print('\n--- view results ---')
show(r)

# Admin download results
r = s.get(urljoin(BASE,'/admin/download_results'))
print('\n--- download results ---')
print(r.status_code)
print(r.text[:400])

print('\nHTTP flow done')
