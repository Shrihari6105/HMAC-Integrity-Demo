"""
server.py - Flask server with HMAC-SHA256 request validation
Demonstrates server-side integrity verification for HTTP POST requests.
"""

from flask import Flask, request, jsonify
import hmac
import hashlib

app = Flask(__name__)

# Shared secret key (in production, store securely via env variable)
SECRET_KEY = "Shrihari_23BCI0083"


def generate_hmac(message: str) -> str:
    """Generate HMAC-SHA256 for a given message using the shared secret key."""
    return hmac.new(
        SECRET_KEY.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()


def verify_hmac(message: str, provided_hmac: str) -> bool:
    """Verify the provided HMAC against the expected HMAC for the message."""
    expected_hmac = generate_hmac(message)
    # Use hmac.compare_digest to prevent timing attacks
    return hmac.compare_digest(expected_hmac, provided_hmac)


@app.route("/transfer", methods=["POST"])
def transfer():
    """
    Endpoint that processes a transfer request.
    Expects query params: transfer, account, hmac
    Rejects the request if HMAC verification fails.
    """
    transfer_amount = request.args.get("transfer")
    account = request.args.get("account")
    provided_hmac = request.args.get("hmac")

    # Check all params are present
    if not all([transfer_amount, account, provided_hmac]):
        return jsonify({
            "status": "error",
            "message": "Missing parameters. Required: transfer, account, hmac"
        }), 400

    # Reconstruct the original message
    message = f"transfer={transfer_amount}&account={account}"

    # Verify HMAC
    if verify_hmac(message, provided_hmac):
        return jsonify({
            "status": "success",
            "message": "Request accepted. HMAC verified — data integrity confirmed.",
            "data": {
                "transfer": transfer_amount,
                "account": account
            }
        }), 200
    else:
        return jsonify({
            "status": "rejected",
            "message": "Request rejected. HMAC mismatch — possible tampering detected.",
            "provided_hmac": provided_hmac,
            "expected_hmac": generate_hmac(f"transfer={transfer_amount}&account={account}")
        }), 403


@app.route("/transfer-no-hmac", methods=["POST"])
def transfer_no_hmac():
    """
    Insecure endpoint with NO integrity check.
    Demonstrates the vulnerability: any tampered value is accepted blindly.
    """
    transfer_amount = request.args.get("transfer")
    account = request.args.get("account")

    if not all([transfer_amount, account]):
        return jsonify({
            "status": "error",
            "message": "Missing parameters."
        }), 400

    return jsonify({
        "status": "success",
        "message": "Request accepted (NO integrity check — vulnerable endpoint).",
        "data": {
            "transfer": transfer_amount,
            "account": account
        }
    }), 200


if __name__ == "__main__":
    print("Starting HMAC verification server on http://127.0.0.1:5000")
    print(f"Secret key in use: {SECRET_KEY}")
    app.run(debug=True)