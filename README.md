# Week 5 – Security Enhancements in Python (SecureNotes)

A small notes web application (stdlib `http.server` + `sqlite3`) in two versions:

| Path | What it is |
|---|---|
| `vulnerable/app_vulnerable.py` | Original app with 17 deliberate weaknesses (**never deploy**) |
| `secure/app_secure.py` | Hardened app – same routes and behaviour, weaknesses fixed |
| `attacks.py` | 17 attack simulations run against both versions |
| `tests/` | 43 tests: functional (both apps) + security controls + attack assertions |
| `run_static_analysis.py` | Bandit scan of both versions |
| `results/` | Saved attack results, Bandit reports, test log |

## Run
```
pip install -r requirements.txt     # cryptography (+ bandit for static analysis)
python run_all.py                   # tests, attack simulation, static analysis
python attacks.py                   # attack table only
python secure/app_secure.py --port 8443        # start hardened server (127.0.0.1)
```
Optional hardened-server configuration (environment): `APP_SECRET_KEY`, `APP_ENC_KEY`
(Fernet key), `APP_ADMIN_PASSWORD`. For TLS pass `--certfile/--keyfile`; otherwise place it
behind a TLS-terminating reverse proxy. Attack simulations only target servers the scripts start
on 127.0.0.1 with throw-away in-memory databases.

Routes: POST /register, POST /login, POST /notes, GET /notes/<id>, GET /search?q=,
GET /download?file=, GET /ping?host=, GET /admin.
In the hardened app, POST requests (except register/login) need the header `X-CSRF-Token`
(value returned by /login).
