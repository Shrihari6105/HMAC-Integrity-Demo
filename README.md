# HTTP Request Integrity Verification Using HMAC-SHA256

A practical demonstration of HTTP parameter tampering and its cryptographic defence using HMAC-SHA256. Built as part of a Cryptography and Network Security course at VIT Vellore.

---

## What This Project Demonstrates

HTTP request parameters — such as transaction amounts or account IDs — can be freely intercepted and modified in transit when no integrity check is in place. This project:

1. **Attacks** a live HTTP endpoint by intercepting and tampering with POST parameters using Burp Suite
2. **Defends** against the same attack using HMAC-SHA256 request signing on a Flask server
3. **Contrasts** a hardened endpoint vs. a deliberately vulnerable one side by side

---

## Tools & Stack

| Layer | Technology |
|---|---|
| Language | Python 3 |
| Server | Flask |
| Crypto | `hmac`, `hashlib` (stdlib) |
| Attack proxy | Burp Suite Community Edition |
| HTTP testing | Postman |

---

## How It Works

### Attack (no integrity check)
```
Client sends:  POST /transfer?transfer=5000&account=B
Attacker intercepts via Burp Suite → modifies transfer=5000 to transfer=7000
Server receives tampered value and accepts it blindly → 200 OK
```

### Defence (HMAC-SHA256)
```
Client computes: HMAC-SHA256("transfer=5000&account=B", secret_key)
Client sends:    POST /transfer?transfer=5000&account=B&hmac=<digest>

Attacker modifies transfer=5000 → 9000, but cannot update the HMAC (no secret key)
Server recomputes HMAC for the received parameters → mismatch detected → 403 Rejected
```

---

## Project Structure

```
HMAC-Verification/
├── server.py        # Flask server with two endpoints (hardened + vulnerable)
├── client_demo.py   # Automated demo script running all 4 scenarios
└── README.md
```

### Endpoints

| Endpoint | Integrity Check | Behaviour |
|---|---|---|
| `POST /transfer` | HMAC-SHA256 | Rejects tampered requests with 403 |
| `POST /transfer-no-hmac` | None | Accepts any value blindly — intentionally vulnerable |

---

## Running Locally

```bash
# 1. Install dependencies
pip install flask requests

# 2. Start the server
python server.py
# → Running on http://127.0.0.1:5000

# 3. In a separate terminal, run the demo
python client_demo.py
```

The demo script runs four scenarios automatically:
- **Demo 1** — Legitimate request with valid HMAC → `200 OK`
- **Demo 2** — Tampered request, HMAC unchanged → `403 Rejected`
- **Demo 3** — Tampered request sent to unprotected endpoint → `200 OK` (blindly accepted)
- **Demo 4** — Local HMAC generation showing the avalanche effect across modified inputs

---

## Key Implementation Detail

```python
# Constant-time comparison — prevents timing-based side-channel attacks
return hmac.compare_digest(expected_hmac, provided_hmac)
```

Using `==` for HMAC comparison leaks information: a Python string comparison short-circuits on the first mismatched byte, so an attacker measuring response times can infer the correct HMAC one byte at a time. `hmac.compare_digest()` runs in constant time regardless of where the mismatch occurs, closing this side channel.

---

## Results

| Scenario | Endpoint | Result |
|---|---|---|
| Legitimate request, valid HMAC | `/transfer` | `200 OK` — Accepted |
| Tampered request, HMAC unchanged | `/transfer` | `403 Rejected` |
| Tampered request, no integrity check | `/transfer-no-hmac` | `200 OK` — Accepted blindly |

---

## Concepts Covered

- HMAC-SHA256 and the avalanche effect
- HTTP parameter tampering via proxy interception
- Timing-based side-channel attacks and constant-time comparison
- Secure vs. insecure endpoint design contrast

---

*Shrihari V — 23BCI0083 | VIT Vellore*
