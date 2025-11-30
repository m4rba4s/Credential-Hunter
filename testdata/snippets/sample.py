"""
Synthetic code snippet to validate context-aware detection.
Contains variables, comments, and strings that look like credentials.
"""

import os

# Realistic names (should boost confidence)
AWS_ACCESS_KEY_ID = "AKIAFAKEFAKE1234567"
AWS_SECRET_ACCESS_KEY = "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEKEY"

# Test/example names (should reduce confidence)
TEST_API_KEY = "sk_test_example_key_for_testing"
DEMO_TOKEN = "demo_token_please_replace"

# Mixed context: JWT in code
jwt_token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0NTYifQ.signature"

# Slack tokens across code/comments
slack_bot = "SLACK_BOT_TOKEN_DUMMY"  # Slack Bot Token
slack_user = "SLACK_USER_TOKEN_DUMMY"

# Stripe keys
stripe_secret = "sk_test_DUMMY_STRIPE_KEY"
stripe_publishable = "pk_test_DUMMY_PUBLISHABLE_KEY"

# Various URIs
psql = "postgres://user:pass@db.example.net:5432/app"
mongo = "mongodb+srv://user:pass@cluster0.example.net/mydb?retryWrites=true&w=majority"

def connect():
    # Placeholder to simulate usage
    return any((AWS_ACCESS_KEY_ID, stripe_secret, jwt_token, psql, mongo))

if __name__ == "__main__":
    print("Synthetic sample loaded; do not use in production.")
