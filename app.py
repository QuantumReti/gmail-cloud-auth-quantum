from flask import Flask, redirect, request, session
import os
import secrets
import requests
from urllib.parse import urlencode
import json
from datetime import timedelta

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.send",
]
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"

def get_env(name):
    return os.environ.get(name, "").strip()

def missing_vars():
    missing = []
    if not get_env("GOOGLE_CLIENT_ID"):
        missing.append("GOOGLE_CLIENT_ID")
    if not get_env("GOOGLE_CLIENT_SECRET"):
        missing.append("GOOGLE_CLIENT_SECRET")
    if not get_env("GOOGLE_REDIRECT_URI"):
        missing.append("GOOGLE_REDIRECT_URI")
    if not get_env("FLASK_SECRET_KEY"):
        missing.append("FLASK_SECRET_KEY")
    return missing

@app.route("/")
def home():
    missing = missing_vars()
    if missing:
        return f"""
        <h2>Missing environment variables</h2>
        <pre>{", ".join(missing)}</pre>
        """, 500
    return """
    <h1>Sun State Digital Gmail OAuth</h1>
    <p><a href="/connect">Connect Gmail</a></p>
    <p><a href="/health">Health Check</a></p>
    <p><a href="/debug-env">Debug Env</a></p>
    """

@app.route("/health")
def health():
    return "OK", 200

@app.route("/debug-env")
def debug_env():
    return f"""
    <h2>Debug Env</h2>
    <pre>
GOOGLE_CLIENT_ID set: {bool(get_env("GOOGLE_CLIENT_ID"))}
GOOGLE_CLIENT_SECRET set: {bool(get_env("GOOGLE_CLIENT_SECRET"))}
GOOGLE_REDIRECT_URI: {get_env("GOOGLE_REDIRECT_URI")}
FLASK_SECRET_KEY set: {bool(get_env("FLASK_SECRET_KEY"))}
    </pre>
    """

@app.route("/connect")
def connect():
    missing = missing_vars()
    if missing:
        return f"""
        <h2>Missing environment variables</h2>
        <pre>{", ".join(missing)}</pre>
        """, 500
    
    session.permanent = True
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state
    session.modified = True
    
    params = {
        "client_id": get_env("GOOGLE_CLIENT_ID"),
        "redirect_uri": get_env("GOOGLE_REDIRECT_URI"),
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "access_type": "offline",
        "prompt": "consent",
        "include_granted_scopes": "true",
        "state": state,
    }
    return redirect(f"{AUTH_URL}?{urlencode(params)}")

@app.route("/oauth/callback")
def oauth_callback():
    session.permanent = True
    session.modified = True
    
    stored_state = session.get("oauth_state")
    returned_state = request.args.get("state")
    code = request.args.get("code")
    error = request.args.get("error")
    
    if error:
        return f"<pre>Error: {error}</pre>", 400
    
    if not stored_state:
        return "No state stored in session. Please start from /connect", 400
    
    if not returned_state:
        return "No state returned from Google", 400
    
    if stored_state != returned_state:
        return f"State mismatch. Expected: {stored_state[:20]}... Got: {returned_state[:20]}...", 400
    
    if not code:
        return "No code returned", 400
    
    token_data = {
        "code": code,
        "client_id": get_env("GOOGLE_CLIENT_ID"),
        "client_secret": get_env("GOOGLE_CLIENT_SECRET"),
        "redirect_uri": get_env("GOOGLE_REDIRECT_URI"),
        "grant_type": "authorization_code",
    }
    
    try:
        token_response = requests.post(TOKEN_URL, data=token_data)
        if token_response.status_code != 200:
            return f"<pre>Token Error:\n{token_response.text}</pre>", 400
        
        token_json = token_response.json()
        
        return f"""
        <h2>✅ SUCCESS</h2>
        <p>Gmail account authenticated successfully!</p>
        <pre>{json.dumps(token_json, indent=2)}</pre>
        <p><a href="/">Back to home</a></p>
        """
    except Exception as e:
        return f"<pre>Error: {str(e)}</pre>", 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)
