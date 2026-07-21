# filepath: puzzle_kit/zk_verifier.py
import hashlib
import json

class ZKVerifier:
    """
    A Fiat-Shamir Non-Interactive Zero-Knowledge Proof (NIZKP) Verifier.
    Proves knowledge of the secret vector s such that:
    A * s = b - e (mod q)  where e is a small error vector.
    """
    def __init__(self, A, b, q=97):
        self.A = A
        self.b = b
        self.q = q
        self.m = len(A)
        self.n = len(A[0])

    def hash_state(self, commitment_t):
        """
        Derive challenge c dynamically using Fiat-Shamir.
        """
        state_str = f"{self.b}:{commitment_t}"
        h = hashlib.sha256(state_str.encode()).hexdigest()
        return int(h, 16) % 2 # c in {0, 1}

    def verify_proof(self, proof_transcript):
        """
        Verifies 80 iterations of the proof transcript.
        Transcript is a list of dictionary items: {"t": [t_i], "z": [z_i]}
        """
        if len(proof_transcript) < 80:
            print("[-] Security level too low: Proof must contain at least 80 rounds.")
            return False

        for r_id, round_proof in enumerate(proof_transcript):
            t = round_proof["t"]
            z = round_proof["z"]

            if len(t) != self.m or len(z) != self.n:
                print(f"[-] Invalid format in round {r_id}")
                return False

            c = self.hash_state(t)

            # Compute A * z (mod q)
            az = []
            for i in range(self.m):
                val = sum(self.A[i][j] * z[j] for j in range(self.n)) % self.q
                az.append(val)

            # Verification step:
            # If c = 0: A * z = A * r = t (mod q)
            # If c = 1: A * z = A * r + A * s = t + b - e (mod q)
            if c == 0:
                for i in range(self.m):
                    diff = (az[i] - t[i]) % self.q
                    if diff > self.q // 2: diff -= self.q
                    if abs(diff) > 2: # Tolerance limit for r's noise
                        print(f"[-] Round {r_id} verification failed for c = 0")
                        return False
            else:
                for i in range(self.m):
                    diff = (az[i] - (t[i] + self.b[i])) % self.q
                    if diff > self.q // 2: diff -= self.q
                    if abs(diff) > 3: # Tolerance limits
                        print(f"[-] Round {r_id} verification failed for c = 1")
                        return False
        return True

if __name__ == "__main__":
    print("[*] ZK Verifier Script loaded.")
