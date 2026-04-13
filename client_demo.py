import hmac
import hashlib
import requests

BASE_URL = "http://127.0.0.1:5000"
SECRET_KEY = "Shrihari_23BCI0083"


# HMAC Generation

def generate_hmac(message: str) -> str:
    """Generate HMAC-SHA256 for a message using the shared secret key."""
    return hmac.new(
        SECRET_KEY.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()


def print_separator(title: str):
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


# Demo 1
def demo_legitimate_request():
    print_separator("DEMO 1: Legitimate Request")

    transfer = "5000"
    account = "B"
    message = f"transfer={transfer}&account={account}"
    hmac_value = generate_hmac(message)

    print(f"  Message   : {message}")
    print(f"  HMAC      : {hmac_value}")

    response = requests.post(
        f"{BASE_URL}/transfer",
        params={"transfer": transfer, "account": account, "hmac": hmac_value}
    )

    print(f"\n  Server Response [{response.status_code}]:")
    print(f"  {response.json()}")


# Demo 2
def demo_tampered_request():
    print_separator("DEMO 2: Tampered Request (HMAC unchanged)")

    # Original values used to generate HMAC
    original_transfer = "5000"
    account = "B"
    message = f"transfer={original_transfer}&account={account}"
    hmac_value = generate_hmac(message)

    # Attacker modifies transfer to 9000, but reuses the original HMAC
    tampered_transfer = "9000"

    print(f"  Original message  : {message}")
    print(f"  HMAC (for 5000)   : {hmac_value}")
    print(f"  Tampered transfer : {tampered_transfer} (HMAC not updated)")

    response = requests.post(
        f"{BASE_URL}/transfer",
        params={"transfer": tampered_transfer, "account": account, "hmac": hmac_value}
    )

    print(f"\n  Server Response [{response.status_code}]:")
    print(f"  {response.json()}")


# Demo 3 
def demo_no_hmac_endpoint():
    print_separator("DEMO 3: Tampered Request — Insecure Endpoint (No HMAC check)")

    tampered_transfer = "9000"
    account = "B"

    print(f"  Sending tampered transfer={tampered_transfer} with NO HMAC to insecure endpoint")

    response = requests.post(
        f"{BASE_URL}/transfer-no-hmac",
        params={"transfer": tampered_transfer, "account": account}
    )

    print(f"\n  Server Response [{response.status_code}]:")
    print(f"  {response.json()}")
    print("\n  Accepted blindly")


# Demo 4
def demo_local_hmac_generation():
    print_separator("DEMO 4: Local HMAC Generation (no server needed)")

    test_cases = [
        ("transfer=5000&account=B", "5000 → B (original)"),
        ("transfer=7000&account=B", "7000 → B (modified amount)"),
        ("transfer=5000&account=C", "5000 → C (modified account)"),
    ]

    for message, label in test_cases:
        hmac_value = generate_hmac(message)
        print(f"\n  [{label}]")
        print(f"  Message : {message}")
        print(f"  HMAC    : {hmac_value}")


# Main 

if __name__ == "__main__":
    print("\nHMAC Request Integrity Demo")
    print("   Shrihari V | 23BCI0083")

    demo_local_hmac_generation()

    print("\n\n─── Server-dependent demos (ensure server.py is running) ───")
    try:
        demo_legitimate_request()
        demo_tampered_request()
        demo_no_hmac_endpoint()
    except requests.exceptions.ConnectionError:
        print("\n Could not connect to server.")
        print("  Start the server first: python server.py")

    print("\n" + "=" * 60)
    print("  Demo complete.")
    print("=" * 60 + "\n")