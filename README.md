## Blockchain Voting System (Flask)

This repository implements a simple election / voting web application using Flask that records votes on a local blockchain-like data structure. It is intended as an educational/demo project showing how votes can be recorded as immutable blocks, not as a hardened production voting system.

Summary
 - Web UI for admin and voter actions (register, login, add candidates, start/close election, vote).
 - Local JSON-backed storage (`storage.json`) for users, admins, candidates, votes and the chain.
 - Lightweight Blockchain implementation with proof-of-work (used to "mine" pending votes into blocks).
 - Simple vote privacy: voters are represented by hashes of usernames (not strong anonymity).

Project layout (key files)
 - `app.py` — Flask application and routes for admin and voter flows, templates rendering and session management.
 - `blockchain.py` — `Blockchain` class: storage load/save, candidate management, vote handling, mining, chain validation and node registry functionality.
 - `check_hash.py` — small utility used to inspect password hashes in `storage.json` (debug/helper script).
 - `storage.json` — runtime data file (created automatically). Holds chain, pending votes, registered users/admins, candidates, and settings like `voting_open`.
 - `requirements.txt` — pinned runtime dependencies.
 - `templates/` and `static/` — HTML templates and CSS used by the Flask UI.
 - Tests: `test_election.py`, `test_http_flow.py`, `test_web_flow.py` (basic test files included).

Dependencies
 - Python 3.8+ recommended
 - See `requirements.txt` for pinned packages. At time of reading the file contains:
   - Flask==2.2.5
   - requests==2.31.0
   - Werkzeug==3.0.0

Quick start (local, development)
1. Create and activate a Python virtual environment (optional but recommended):
   - Windows PowerShell:
     ```powershell
     python -m venv .venv; .\.venv\Scripts\Activate.ps1
     ```
2. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```
3. Start the Flask app:
   ```powershell
   python app.py
   ```
4. Open the app in a browser: http://127.0.0.1:5000

Default accounts / demo credentials
 - Admin (created on first run in generated `storage.json`):
   - username: `admin`
   - password: `adminpass` (initial default)

High-level flows
 - Admin:
   - Register / Login (`/admin/register`, `/admin/login`)
   - Add candidates (`/admin/add_candidate`)
   - Start / Close elections (`/admin/start_election`, `/admin/close_election`)
   - View dashboard and exported results
 - Voter:
   - Register / Login (`/voter/register`, `/voter/login`)
   - Cast a vote from `/voter/dashboard` while `voting_open` is true

Important implementation details
 - Storage format (`storage.json`): JSON object with keys such as `chain`, `pending_votes`, `voters`, `users`, `admins`, `candidates`, `voting_open`, `nodes`, and `results`.
 - Blocks: each block has `index`, `timestamp`, `vote` (or `null`), `proof`, `previous_hash`, and `hash` (SHA-256 of block JSON). `vote` stores a token, `candidate_id`, `candidate` name and timestamp.
 - Proof-of-work: implemented in `Blockchain.proof_of_vote()` — a simple loop checking that SHA-256(last_hash + proof) starts with a difficulty number of zeros (default difficulty = 3 in code). Mining is used to convert pending votes into blocks.
 - Vote handling: `Blockchain.add_vote(voter_hash, candidate_id)` verifies election is open, the voter hasn't already voted, the candidate exists, then appends a pending vote and records the voter's hashed id in `voters` to prevent double voting. Mining is done by `mine_pending_votes()`.
 - Chain validation: `valid_chain()` verifies that each block's `previous_hash` matches the previous block's `hash` and that the stored `hash` is consistent (by recomputing the block hash without the `hash` field).
 - Node registry & consensus primitives: `register_node`, `replace_chain` and `valid_chain` exist for multi-node capabilities but there is no networked consensus automation in the current app; these are placeholders for experimentation.

Storage examples & notes
 - On first run, if `storage.json` doesn't exist, `Blockchain` creates a genesis block (`index=0`) and a default admin with username `admin` and password hash for `adminpass`.
 - `storage.json` in this repo snapshot contains multiple example blocks in `chain`, several users, and `admins`. Password hash formats vary (some are scrypt or plain SHA-256 hashes depending on history/migrations). The code reads whatever value is in `admins[*]['password_hash']` and compares SHA-256 hashes created by `hashlib.sha256(password.encode()).hexdigest()` in `app.py`.

Routes (principal)
 - GET `/` — landing page
 - GET/POST `/admin/register` — register admin
 - GET/POST `/admin/login` — admin login
 - GET `/admin` — admin dashboard
 - POST `/admin/add_candidate` — add a candidate (admin)
 - POST `/admin/start_election` or `/admin/start_election` (duplicate endpoints in code) — start election
 - POST `/admin/close_election` or `/admin/end_election` — close election and finalize
 - GET/POST `/voter/register` — voter registration
 - GET/POST `/voter/login` — voter login
 - GET/POST `/voter/dashboard` — view candidates and cast vote (POST casts vote)
 - GET `/results` — public results page (after election end)

Tests
 - A few test files exist (`test_election.py`, `test_http_flow.py`, `test_web_flow.py`) meant for pytest. To run tests:
   ```powershell
   pip install pytest
   pytest -q
   ```
 - Tests may assume a clean `storage.json` or manipulate it; back up important `storage.json` before running tests.

Security & production notes (must-read)
 - This project is an educational demo. DO NOT use it for real elections without a thorough security and privacy review.
 - Password hashing: the app currently uses a simple SHA-256-based hash function in `app.py` for credential checks. Some stored hashes use stronger schemes (scrypt) — there is inconsistency. For production, use `werkzeug.security.generate_password_hash` and `check_password_hash` consistently (with a modern algorithm like pbkdf2/argon2/scrypt) and remove plaintext/weak hashes.
 - Secrets: `app.secret_key` is hard-coded in `app.py`. Use environment variables or a secure secrets store in production.
 - HTTPS: Always serve via HTTPS and configure proper CORS / session security.

Developer notes & next steps
 - Improve password handling and migrate legacy hashes with a safe upgrade path.
 - Add API endpoints for chain/blocks visibility and node-to-node sync with secure auth.
 - Add tests for concurrency and double-vote scenarios.
 - Consider replacing PoW with a more appropriate signing/consensus scheme for vote integrity and privacy.

Contact / attribution
 - This repository was prepared as an educational demo combining Flask and a minimal blockchain-like storage for votes. See source files for implementation details.

If you'd like, I can also:
 - Add a README section showing example `curl` requests for the main endpoints.
 - Improve password handling and migrate `storage.json` to use `werkzeug` password hashing consistently.

---
Last updated: auto-generated from repository sources.
