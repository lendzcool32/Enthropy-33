# filepath: puzzle_kit/app.py
"""
ENTROPY-33 Flask Web Gateway
Handles Phase 3 (Lattice Challenge) and Phase 4 (ZK Verification).
Can be deployed easily to Render, Heroku, or a VPS.
"""
from flask import Flask, jsonify, request, send_file
from lattice_challenge import LatticeChallenge
from zk_verifier import ZKVerifier
import json

app = Flask(__name__)
challenge = LatticeChallenge()

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
    import os
    stego_path = os.path.join(os.path.dirname(__file__), "entropy_stego.png")
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
        
        # Verify secret
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
        
        # Verify proof
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
    import os
    # For local test, pre-generate stego image
    if not os.path.exists("entropy_stego.png"):
        from PIL import Image
        from stego_injector import derive_key, encrypt_payload, embed_payload
        from custom_vm import assemble
        
        # Generate clean baseline and embed bytecode
        img = Image.new("RGB", (256, 256), color=(40, 44, 52))
        img.save("entropy_baseline.png")
        
        # Load sample assembly to execute password "3301"
        with open("entropy_baseline.png", "rb") as f:
            baseline_hash = hashlib.sha256(f.read()).hexdigest()
            
        asm = "IN\\nPUSH 51\\nXOR\\nJZ char2\\nJMP fail\\nchar2:\\nIN\\nPUSH 51\\nXOR\\nJZ char3\\nJMP fail\\nchar3:\\nIN\\nPUSH 48\\nXOR\\nJZ char4\\nJMP fail\\nchar4:\\nIN\\nPUSH 49\\nXOR\\nJZ success\\nJMP fail\\nfail:\\nPUSH 70\\nOUT\\nHALT\\nsuccess:\\nPUSH 104\\nOUT\\nPUSH 116\\nOUT\\nPUSH 116\\nOUT\\nPUSH 112\\nOUT\\nPUSH 58\\nOUT\\nPUSH 47\\nOUT\\nPUSH 47\\nOUT\\nPUSH 108\\nOUT\\nPUSH 97\\nOUT\\nPUSH 116\\nOUT\\nPUSH 116\\nOUT\\nPUSH 105\\nOUT\\nPUSH 99\\nOUT\\nPUSH 101\\nOUT\\nHALT"
        bytecode = assemble(asm.replace("\\n", "\n"))
        key = derive_key("Silence is golden, entropy is absolute.", baseline_hash)
        enc_payload = encrypt_payload(bytecode, key)
        embed_payload("entropy_baseline.png", enc_payload, "entropy_stego.png", "Silence is golden, entropy is absolute.")
        os.remove("entropy_baseline.png")
        
    app.run(host="0.0.0.0", port=5000)
