# filepath: puzzle_kit/app.py
from flask import Flask, jsonify, request, send_file
from lattice_challenge import LatticeChallenge
from zk_verifier import ZKVerifier
import os
import hashlib
from PIL import Image
from stego_injector import get_pixel_hash, derive_key, encrypt_payload, inject_custom_chunk
from custom_vm import assemble

app = Flask(__name__)
challenge = LatticeChallenge()

# -----------------------------------------------------------------------------
# Module-level Boot/Setup Block (Runs automatically on Render startup)
# -----------------------------------------------------------------------------
dir_name = os.path.dirname(__file__)
stego_path = os.path.join(dir_name, "entropy_stego.png")

if not os.path.exists(stego_path):
    print("[*] Performing first-time server stego-beacon generation...")
    temp_baseline = os.path.join(dir_name, "temp_baseline.png")
    img = Image.new("RGB", (256, 256), color=(40, 44, 52))
    img.save(temp_baseline)
    
    asm = """
    IN
    PUSH 51
    XOR
    JZ char2
    JMP fail
    char2:
    IN
    PUSH 51
    XOR
    JZ char3
    JMP fail
    char3:
    IN
    PUSH 48
    XOR
    JZ char4
    JMP fail
    char4:
    IN
    PUSH 49
    XOR
    JZ success
    JMP fail
    fail:
    PUSH 70
    OUT
    HALT
    success:
    PUSH 104
    OUT
    PUSH 116
    OUT
    PUSH 116
    OUT
    PUSH 112
    OUT
    PUSH 58
    OUT
    PUSH 47
    OUT
    PUSH 47
    OUT
    PUSH 108
    OUT
    PUSH 97
    OUT
    PUSH 116
    OUT
    PUSH 116
    OUT
    PUSH 105
    OUT
    PUSH 99
    OUT
    PUSH 101
    OUT
    HALT
    """
    bytecode = assemble(asm)
    
    pixel_hash = get_pixel_hash(temp_baseline)
    key = derive_key(pixel_hash)
    enc_payload = encrypt_payload(bytecode, key)
    
    inject_custom_chunk(temp_baseline, "eNtR", enc_payload, stego_path)
    
    if os.path.exists(temp_baseline):
        os.remove(temp_baseline)

# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "msg": "Silence is golden, entropy is absolute. Seek the beacon of trial.",
        "endpoints": {
            "/stego-beacon": "Download the raw Phase 1 Steganographic image.",
            "/lattice": "Query the Phase 3 Lattice LWE challenge parameters.",
            "/submit-secret": "POST candidate secret vector [s0, s1, s2, s3] to unlock Phase 4 instructions.",
            "/submit-proof": "POST the 80-round JSON Fiat-Shamir proof transcript to claim victory."
        }
    })

@app.route("/stego-beacon", methods=["GET"])
def get_stego_image():
    if not os.path.exists(stego_path):
        return jsonify({"error": "Stego beacon image not yet compiled. Ask host to run setup."}), 500
    return send_file(stego_path, mimetype="image/png")

@app.route("/lattice", methods=["GET"])
def get_lattice_challenge():
    return jsonify({
        "q": challenge.q,
        "n": challenge.n,
        "m": challenge.m,
        "A": challenge.A,
        "b": challenge.b,
        "info": "We have added a small discrete Gaussian error e. Recover secret s such that A*s + e = b (mod q)."
    })

@app.route("/submit-secret", methods=["POST"])
def submit_secret():
    try:
        data = request.get_json()
        candidate = data.get("secret")
        if not candidate or len(candidate) != challenge.n:
            return jsonify({"error": "Invalid payload format. Must supply a list of size 4."}), 400
        
        if challenge.verify_solution(candidate):
            return jsonify({
                "status": "UNLOCKED",
                "message": "Lattice secret confirmed. Prepare for Phase 4: Zero-Knowledge Verification.",
                "instructions": "Demonstrate knowledge of s without revealing it. Submit an 80-round Fiat-Shamir NIZKP transcript.",
                "FS_challenge_format": "Derive challenge c_i = SHA256(b || t_i) % 2. Compute response z_i = r_i + c_i * s (mod q). Submit to /submit-proof as list of dicts: [{'t': [t0,..,t7], 'z': [z0,..,z3]}] of length 80."
            })
        else:
            return jsonify({"status": "REJECTED", "message": "Incorrect secret key. Entropy remains bound."}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/submit-proof", methods=["POST"])
def submit_proof():
    try:
        data = request.get_json()
        transcript = data.get("transcript")
        if not transcript or len(transcript) < 80:
            return jsonify({"error": "Transcript must contain at least 80 rounds of proof."}), 400
        
        verifier = ZKVerifier(challenge.A, challenge.b, challenge.q)
        if verifier.verify_proof(transcript):
            return jsonify({
                "status": "AUTHENTICATED",
                "message": "Proof verified. Welcome to the Inner Circle.",
                "coordinates": "45.1096 N, -122.6801 W",
                "signature": "SHA256(entropy-33-sig): a3b4976df8bc4196da3c..."
            })
        else:
            return jsonify({"status": "INVALID_PROOF", "message": "Verification failed on proof constraints."}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
