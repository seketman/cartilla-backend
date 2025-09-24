from flask import Flask, redirect, request, jsonify, session
from authlib.integrations.flask_client import OAuth
import jwt
import datetime
import os

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "clave-super-secreta")

CARTILLAIA_SECRET = os.getenv("CARTILLAIA_SECRET", "jwt-cartillaia-secret")

SERVER_SCHEME = os.getenv("SERVER_SCHEME", "http")
SERVER_HOST = os.getenv("SERVER_HOST", "localhost")
SERVER_PORT = int(os.getenv("SERVER_PORT", 5000))
SERVER_URI = f"{SERVER_SCHEME}://{SERVER_HOST}:{SERVER_PORT}"
CALLBACK_URI = os.getenv("CALLBACK_URI", f"{SERVER_URI}/auth/callback")

# Config multi-tenant: cada obra social tiene su Tenant + Client ID + Secret
# En un sistema real, esto lo guardarías en una DB
OBRAS_SOCIALES = {
    "medife": {
        "tenant_id": os.getenv("MEDIFE_TENANT_ID"),
        "client_id": os.getenv("MEDIFE_CLIENT_ID"),
        "client_secret": os.getenv("MEDIFE_CLIENT_SECRET")
    },
    "osde": {
        "tenant_id": os.getenv("OSDE_TENANT_ID"),
        "client_id": os.getenv("OSDE_CLIENT_ID"),
        "client_secret": os.getenv("OSDE_CLIENT_SECRET")
    }
}

oauth = OAuth(app)

def get_oidc_provider(os_key):
    config = OBRAS_SOCIALES[os_key]
    return oauth.register(
        name=f"azure_{os_key}",
        client_id=config["client_id"],
        client_secret=config["client_secret"],
        server_metadata_url=f"https://login.microsoftonline.com/{config['tenant_id']}/v2.0/.well-known/openid-configuration",
        client_kwargs={"scope": "openid profile email offline_access"}  # offline_access = refresh_token
    )

def generate_cartillaia_jwt(userinfo):
    payload = {
        "sub": userinfo["sub"],
        "email": userinfo.get("email") or userinfo.get("preferred_username"),
        "name": userinfo.get("name"),
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15),
        "iss": "CartillaIA"
    }
    return jwt.encode(payload, CARTILLAIA_SECRET, algorithm="HS256")

@app.route("/login/<os_key>")
def login(os_key):
    provider = get_oidc_provider(os_key)
    return provider.authorize_redirect(
        redirect_uri=f"{CALLBACK_URI}/{os_key}"
    )

@app.route("/auth/callback/<os_key>")
def auth_callback(os_key):
    provider = get_oidc_provider(os_key)
    token = provider.authorize_access_token()
    userinfo = token.get("userinfo") or provider.parse_id_token(token)

    # Guardar refresh_token seguro en backend
    session["refresh_token"] = token.get("refresh_token")
    session["os_key"] = os_key
    session["sub"] = userinfo["sub"]

    # Emitir JWT propio de CartillaIA
    cartillaia_jwt = generate_cartillaia_jwt(userinfo)

    return redirect(f"{SERVER_URI}/dashboard?token={cartillaia_jwt}")

@app.route("/me")
def me():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "missing_token"}), 401
    
    token = auth_header.split(" ")[1]
    try:
        decoded = jwt.decode(token, CARTILLAIA_SECRET, algorithms=["HS256"])
        return jsonify(decoded)
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "token_expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "invalid_token"}), 401

@app.route("/refresh")
def refresh():
    if "refresh_token" not in session or "os_key" not in session:
        return jsonify({"error": "not_authenticated"}), 401
    
    provider = get_oidc_provider(session["os_key"])
    new_token = provider.refresh_token(
        provider.client_kwargs["server_metadata"]["token_endpoint"],
        refresh_token=session["refresh_token"]
    )

    userinfo = provider.parse_id_token(new_token)

    # Guardar el nuevo refresh_token si vino actualizado
    if "refresh_token" in new_token:
        session["refresh_token"] = new_token["refresh_token"]

    # Emitir nuevo JWT de CartillaIA
    new_cartillaia_jwt = generate_cartillaia_jwt(userinfo)

    return jsonify({"token": new_cartillaia_jwt})

if __name__ == "__main__":
    app.run(debug=True)
