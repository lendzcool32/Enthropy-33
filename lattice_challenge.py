# filepath: puzzle_kit/lattice_challenge.py
import random

class LatticeChallenge:
    """
    Defines a Learning with Errors (LWE) instance over Z_q.
    q = 97 (prime modulus)
    n = 4 (secret key dimension)
    m = 8 (number of equations/samples)
    """
    def __init__(self):
        self.q = 97
        self.n = 4
        self.m = 8
        self.secret = [2, 96, 1, 95] # Secret vector s (represented in [0, q-1])
        self.errors = [1, 0, -1, 1, 0, 1, -1, 0] # Error vector e
        
        # Deterministically generate A using seed for reproducibility
        self.A = []
        rng = random.Random(1337)
        for _ in range(self.m):
            row = [rng.randint(0, self.q - 1) for _ in range(self.n)]
            self.A.append(row)
            
        # b = A * s + e (mod q)
        self.b = []
        for i in range(self.m):
            ax = sum(self.A[i][j] * self.secret[j] for j in range(self.n))
            self.b.append((ax + self.errors[i]) % self.q)

    def print_challenge(self):
        print(f"Modulus q = {self.q}")
        print(f"Dimension n = {self.n}")
        print(f"Samples m = {self.m}")
        print("Matrix A:")
        for row in self.A:
            print(f"  {row}")
        print(f"Vector b = {self.b}")

    def verify_solution(self, candidate_s):
        if len(candidate_s) != self.n:
            return False
        # If candidate is correct, b - A*cand (mod q) should be close to 0 (the small error vector)
        for i in range(self.m):
            ax = sum(self.A[i][j] * candidate_s[j] for j in range(self.n))
            diff = (self.b[i] - ax) % self.q
            if diff > self.q // 2:
                diff -= self.q
            if abs(diff) > 1:
                return False
        return True

if __name__ == "__main__":
    challenge = LatticeChallenge()
    challenge.print_challenge()
    print(f"Verify correct key: {challenge.verify_solution([2, 96, 1, 95])}")
    print(f"Verify incorrect key: {challenge.verify_solution([0, 0, 0, 0])}")
