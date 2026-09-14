#!/usr/bin/env python3
"""Generate an API key for API_KEY in .env."""
import secrets

if __name__ == "__main__":
    print(secrets.token_urlsafe(32))
