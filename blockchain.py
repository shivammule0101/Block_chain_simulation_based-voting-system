import time
import hashlib
import json
import uuid

class Blockchain:
    def __init__(self, storage_path):
        self.storage_path = storage_path
        self._load_storage()

    def _load_storage(self):
        try:
            with open(self.storage_path, 'r') as f:
                data = json.load(f)
        except FileNotFoundError:
            data = {
                'chain': [],
                'pending_votes': [],
                'voters': [],
                'users': [],
                'voting_open': False,  # Initially closed until admin starts election
                'election_started': False,  # Track if election has been started
                'nodes': [],
                'candidates': [],  # List of registered candidates
                'admins': [{
                    'username': 'admin',
                    'password_hash': '',  # set below
                    'is_super_admin': True,  # first admin is super admin
                    'email': 'admin@example.com',  # default email
                    'created_at': time.time()
                }]
            }
            genesis = self._create_block(index=0, previous_hash='0', vote=None, proof=0, timestamp=time.time())
            data['chain'].append(genesis)
            data['admins'][0]['password_hash'] = hashlib.sha256('adminpass'.encode()).hexdigest()
            with open(self.storage_path, 'w') as f:
                json.dump(data, f, indent=2)
        if 'voting_open' not in data:
            data['voting_open'] = True
        if 'nodes' not in data:
            data['nodes'] = []
        if 'users' not in data:
            data['users'] = []
        # migrate single admin to admins list if needed
        if 'admin' in data and 'admins' not in data:
            data['admins'] = [{
                'username': data['admin']['username'],
                'password_hash': data['admin']['password_hash'],
                'is_super_admin': True,
                'created_at': time.time()
            }]
            del data['admin']
        if 'admins' not in data:
            data['admins'] = [{
                'username': 'admin',
                'password_hash': hashlib.sha256('adminpass'.encode()).hexdigest(),
                'is_super_admin': True,
                'created_at': time.time()
            }]
        self.data = data

    def _save(self):
        with open(self.storage_path, 'w') as f:
            json.dump(self.data, f, indent=2)

    @staticmethod
    def hash_block(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def last_block(self):
        return self.data['chain'][-1]

    def add_candidate(self, name, party_name):
        """Add a new candidate to the election."""
        candidate_id = str(uuid.uuid4())
        candidate = {
            'id': candidate_id,
            'name': name,
            'party_name': party_name,
            'created_at': time.time()
        }
        self.data.setdefault('candidates', []).append(candidate)
        self._save()
        return candidate

    def update_candidate(self, candidate_id, name, party_name):
        """Update an existing candidate's information."""
        candidates = self.data.get('candidates', [])
        for candidate in candidates:
            if candidate['id'] == candidate_id:
                candidate['name'] = name
                candidate['party_name'] = party_name
                candidate['updated_at'] = time.time()
                self._save()
                return candidate
        raise ValueError('Candidate not found')

    def delete_candidate(self, candidate_id):
        """Delete a candidate from the election."""
        candidates = self.data.get('candidates', [])
        for i, candidate in enumerate(candidates):
            if candidate['id'] == candidate_id:
                del candidates[i]
                self._save()
                return True
        return False

    def get_candidates(self):
        """Get list of all candidates."""
        return self.data.get('candidates', [])

    def add_vote(self, voter_hash, candidate_id):
        """Add a vote for a specific candidate."""
        if not self.data['voting_open']:
            raise ValueError('Voting is closed')
        if voter_hash in self.data['voters']:
            raise ValueError('Voter has already voted')
        
        # Verify candidate exists
        candidates = self.data.get('candidates', [])
        candidate = next((c for c in candidates if c['id'] == candidate_id), None)
        if not candidate:
            raise ValueError('Invalid candidate')
        
        self.data['voters'].append(voter_hash)
        vote_token = uuid.uuid4().hex
        vote = {
            'token': vote_token,
            'candidate_id': candidate_id,
            'candidate': candidate['name'],  # Store name for historical record
            'timestamp': time.time()
        }
        self.data['pending_votes'].append(vote)
        self._save()
        return vote

    def _create_block(self, index, previous_hash, vote, proof, timestamp):
        block = {
            'index': index,
            'timestamp': timestamp,
            'vote': vote,
            'proof': proof,
            'previous_hash': previous_hash
        }
        block['hash'] = self.hash_block(block)
        return block

    def proof_of_vote(self, last_hash, difficulty=3):
        proof = 0
        target = '0' * difficulty
        while True:
            guess = f'{last_hash}{proof}'.encode()
            guess_hash = hashlib.sha256(guess).hexdigest()
            if guess_hash[:difficulty] == target:
                return proof
            proof += 1

    def mine_pending_votes(self, difficulty=3):
        mined_blocks = []
        while self.data['pending_votes']:
            vote = self.data['pending_votes'].pop(0)
            last_hash = self.last_block()['hash']
            proof = self.proof_of_vote(last_hash, difficulty=difficulty)
            block = self._create_block(index=len(self.data['chain']), previous_hash=last_hash, vote=vote, proof=proof, timestamp=time.time())
            self.data['chain'].append(block)
            mined_blocks.append(block)
        self._save()
        return mined_blocks

    def close_voting_and_finalize(self, difficulty=3):
        if not self.data['voting_open']:
            return {'status': 'already_closed'}
        self.data['voting_open'] = False
        self.data['election_started'] = False
        mined = self.mine_pending_votes(difficulty=difficulty)
        self._save()
        return {'status': 'closed', 'mined_blocks': mined}
        
    def start_election(self):
        """Start a new election."""
        if self.data.get('election_started', False):
            raise ValueError('Election is already in progress')
            
        self.data['election_started'] = True
        self.data['voting_open'] = True
        self.data['voters'] = []  # Reset voters list
        self.data['pending_votes'] = []  # Reset pending votes
        self._save()
        return {'status': 'started'}

    def close_election(self):
        """Close the current election and finalize results."""
        if not self.data.get('election_started', False):
            raise ValueError('No election is in progress')
            
        self.data['voting_open'] = False
        self.data['election_started'] = False
        # Mine any remaining votes
        mined = self.mine_pending_votes()
        self._save()
        return {'status': 'closed', 'mined_blocks': mined}

    def get_chain_public(self):
        public_chain = []
        for block in self.data['chain']:
            blk = {
                'index': block['index'],
                'timestamp': block['timestamp'],
                'candidate': block['vote']['candidate'] if block['vote'] else None,
                'proof': block['proof'],
                'previous_hash': block['previous_hash'],
                'hash': block['hash']
            }
            public_chain.append(blk)
        return public_chain

    def get_results(self):
        if self.data['voting_open']:
            raise ValueError('Voting still open: results unavailable')
        counts = {}
        for block in self.data['chain']:
            if block['vote'] and 'candidate' in block['vote']:
                c = block['vote']['candidate']
                counts[c] = counts.get(c, 0) + 1
        return counts

    def register_node(self, node_url):
        if node_url not in self.data['nodes']:
            self.data['nodes'].append(node_url)
            self._save()
        return self.data['nodes']

    def valid_chain(self, chain):
        for i in range(1, len(chain)):
            prev = chain[i-1]
            block = chain[i]
            if block['previous_hash'] != prev['hash']:
                return False
            block_copy = dict(block)
            block_hash = block_copy.get('hash')
            recomputed = self.hash_block({k:block_copy[k] for k in block_copy if k != 'hash'})
            if block_hash != recomputed:
                return False
        return True

    def replace_chain(self, new_chain):
        if len(new_chain) <= len(self.data['chain']):
            return False
        if not self.valid_chain(new_chain):
            return False
        self.data['chain'] = new_chain
        self._save()
        return True
