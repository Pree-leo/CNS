import os
import json
import hashlib
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
import io

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB max file size

DATA_DIR = os.path.join(os.path.expanduser("~"), "DSA_Verifier_Data")
HISTORY_FILE = os.path.join(DATA_DIR, "verification_history.json")


def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def save_history(history):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)


def add_history(file_name, result, sha):
    history = load_history()
    history.append({
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "file": file_name,
        "result": result,
        "sha256": sha,
    })
    save_history(history)


def key_fingerprint(public_key):
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fp = hashlib.sha256(der).hexdigest()
    return ":".join(fp[i:i + 4] for i in range(0, 32, 4))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/metrics", methods=["GET"])
def get_metrics():
    history = load_history()
    total = len(history)
    valid = sum(1 for h in history if h.get("result") == "VALID")
    tamper = sum(1 for h in history if h.get("result") == "INVALID")
    return jsonify({
        "total": total,
        "valid": valid,
        "tamper": tamper,
        "algorithm": "DSA 2048-bit",
        "digest": "SHA-256"
    })


@app.route("/api/history", methods=["GET"])
def get_history():
    return jsonify(list(reversed(load_history())))


@app.route("/api/clear-history", methods=["POST"])
def clear_history():
    save_history([])
    return jsonify({"status": "success", "message": "History cleared"})


@app.route("/api/generate-keys", methods=["POST"])
def api_generate_keys():
    data = request.get_json() or {}
    passphrase = data.get("passphrase") or None

    private_key = dsa.generate_private_key(key_size=2048)
    public_key = private_key.public_key()

    if passphrase:
        enc = serialization.BestAvailableEncryption(passphrase.encode())
    else:
        enc = serialization.NoEncryption()

    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc).decode("utf-8")
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("utf-8")

    params = public_key.public_numbers().parameter_numbers
    fp = key_fingerprint(public_key)

    return jsonify({
        "status": "success",
        "private_pem": private_pem,
        "public_pem": public_pem,
        "key_size": private_key.key_size,
        "q_bits": params.q.bit_length(),
        "encrypted": bool(passphrase),
        "fingerprint": fp
    })


@app.route("/api/sign", methods=["POST"])
def api_sign():
    if "file" not in request.files or "key" not in request.files:
        return jsonify({"status": "error", "message": "Both file and private key (.pem) are required"}), 400

    target_file = request.files["file"]
    key_file = request.files["key"]
    passphrase = request.form.get("passphrase") or None

    file_bytes = target_file.read()
    key_bytes = key_file.read()

    try:
        private_key = serialization.load_pem_private_key(
            key_bytes, password=passphrase.encode() if passphrase else None)
    except Exception as e:
        return jsonify({"status": "error", "message": f"Could not decrypt/read private key: {str(e)}"}), 400

    if not isinstance(private_key, dsa.DSAPrivateKey):
        return jsonify({"status": "error", "message": "The selected key is not a DSA private key"}), 400

    signature = private_key.sign(file_bytes, hashes.SHA256())
    r, s = decode_dss_signature(signature)
    digest = hashlib.sha256(file_bytes).hexdigest()
    fp = key_fingerprint(private_key.public_key())

    manifest = {
        "file": target_file.filename,
        "sha256": digest,
        "signed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "key_fingerprint": fp,
    }

    return jsonify({
        "status": "success",
        "file_name": target_file.filename,
        "size": len(file_bytes),
        "sha256": digest,
        "r": f"{r:x}",
        "s": f"{s:x}",
        "fingerprint": fp,
        "signature_hex": signature.hex(),
        "manifest": manifest
    })


@app.route("/api/verify", methods=["POST"])
def api_verify():
    if "file" not in request.files or "signature" not in request.files or "key" not in request.files:
        return jsonify({"status": "error", "message": "Target file, signature (.sig), and public key (.pem) are required"}), 400

    target_file = request.files["file"]
    sig_file = request.files["signature"]
    key_file = request.files["key"]
    info_file = request.files.get("info")

    file_bytes = target_file.read()
    sig_bytes = sig_file.read()
    key_bytes = key_file.read()

    try:
        public_key = serialization.load_pem_public_key(key_bytes)
    except Exception as e:
        return jsonify({"status": "error", "message": f"Could not read public key: {str(e)}"}), 400

    if not isinstance(public_key, dsa.DSAPublicKey):
        return jsonify({"status": "error", "message": "The selected key is not a DSA public key"}), 400

    current_hash = hashlib.sha256(file_bytes).hexdigest()

    try:
        r, s = decode_dss_signature(sig_bytes)
    except Exception:
        r, s = None, None

    try:
        public_key.verify(sig_bytes, file_bytes, hashes.SHA256())
        valid = True
    except InvalidSignature:
        valid = False

    signed_hash = None
    if info_file:
        try:
            info_data = json.loads(info_file.read().decode("utf-8"))
            signed_hash = info_data.get("sha256")
        except Exception:
            pass

    verdict_text = "VALID" if valid else "INVALID"
    add_history(target_file.filename, verdict_text, current_hash)

    return jsonify({
        "status": "success",
        "valid": valid,
        "file_name": target_file.filename,
        "current_hash": current_hash,
        "signed_hash": signed_hash,
        "r": f"{r:x}" if r is not None else None,
        "s": f"{s:x}" if s is not None else None,
        "fingerprint": key_fingerprint(public_key)
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
