from blockchain import Blockchain
from pathlib import Path
import hashlib

STORAGE = Path(__file__).parent / "storage.json"
bc = Blockchain(str(STORAGE))
print('initial election_started:', bc.data.get('election_started'))
print('initial voting_open:', bc.data.get('voting_open'))
print('initial candidates:', bc.get_candidates())
# add a candidate
c = bc.add_candidate('Test Candidate','Test Party')
print('added candidate id:', c['id'])
# start election
try:
    bc.start_election()
    print('started election ->', bc.data.get('election_started'), bc.data.get('voting_open'))
except Exception as e:
    print('start error:', e)
# simulate a voter
voter_hash = hashlib.sha256('voter1'.encode()).hexdigest()
try:
    vote = bc.add_vote(voter_hash, c['id'])
    print('vote token', vote['token'])
except Exception as e:
    print('vote error:', e)
# mine
mined = bc.mine_pending_votes()
print('mined blocks:', len(mined))
# close election
try:
    res = bc.close_election()
    print('close res:', res)
except Exception as e:
    print('close error:', e)
# get results
try:
    print('results:', bc.get_results())
except Exception as e:
    print('get_results error:', e)
