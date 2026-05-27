"""UPSU Protocol Simulation — verify correctness with modular arithmetic.

Models DH-based PRF in a prime-order subgroup of a safe-prime field.
H(x) maps to a quadratic residue whose order is SCALAR_ORDER.
Scalar operations (keys, inverses) are modulo SCALAR_ORDER.
"""

import hashlib
import random
import sys

# ── Group parameters ───────────────────────────────────────────────
# We generate a safe prime (p = 2q+1, q prime) at startup.
# Practical approach: use a 160-bit safe prime (fast, still > 2^128).

def _mr(n, k=25):
    if n < 2: return False
    if n % 2 == 0: return n == 2
    r, d = 0, n - 1
    while d % 2 == 0: r += 1; d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1: continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else: return False
    return True


def _gen_safe_prime(bits=168):
    """Generate a safe prime p = 2q+1 with q prime."""
    while True:
        q = random.getrandbits(bits - 1) | (1 << (bits - 1)) | 1  # odd, msb set
        if _mr(q):
            p = 2 * q + 1
            if _mr(p):
                return p, q


random.seed(42)  # deterministic for reproducibility
FIELD_MODULUS, SCALAR_ORDER = _gen_safe_prime(168)
assert FIELD_MODULUS == 2 * SCALAR_ORDER + 1
assert FIELD_MODULUS > 2 ** 128

# Keys (random scalars mod SCALAR_ORDER — always invertible since q is prime)
k0 = random.randint(1, SCALAR_ORDER - 1)
k1 = random.randint(1, SCALAR_ORDER - 1)
k0_inv = pow(k0, -1, SCALAR_ORDER)
k1_inv = pow(k1, -1, SCALAR_ORDER)

print(f"[Generated safe prime: SCALAR_ORDER ~ 2^{SCALAR_ORDER.bit_length()}]", file=sys.stderr)

# ── PRF primitives ─────────────────────────────────────────────────
def HashToCurve(x: int) -> int:
    """H(x) into the subgroup of quadratic residues (order = SCALAR_ORDER)."""
    raw = hashlib.sha256(str(x).encode()).digest()
    h = int.from_bytes(raw, 'little') % FIELD_MODULUS
    return pow(h, 2, FIELD_MODULUS)  # square → subgroup


def ComputeSinglePRF(x: int, sk: int) -> int:
    """F_sk(x) = H(x)^sk mod FIELD_MODULUS."""
    return pow(HashToCurve(x), sk, FIELD_MODULUS)


def RaiseToKey(v: int, sk: int) -> int:
    """v^sk mod FIELD_MODULUS."""
    return pow(v, sk, FIELD_MODULUS)


def StripKey(v: int, skinv: int) -> int:
    """v^{sk^{-1}} mod FIELD_MODULUS (skinv is modulo SCALAR_ORDER)."""
    return pow(v, skinv, FIELD_MODULUS)


def HashPRFToUint128(v: int) -> int:
    """Hash PRF value to uint128_t for PSI."""
    raw = hashlib.blake2b(str(v).encode(), digest_size=16).digest()
    return int.from_bytes(raw, 'little')


# ── Set helpers ────────────────────────────────────────────────────
def ToSet(v: list) -> set:
    return set(v)


def PRF_Intersect(a: list, b: list) -> list:
    sb = ToSet(b)
    return [x for x in a if x in sb]


# ── Protocol ───────────────────────────────────────────────────────
class PartyState:
    """Simulated party state, mirroring the C++ Party struct."""
    def __init__(self, name: str, own_set: list, union: list):
        self.name = name
        self.X = sorted(set(own_set))
        self.U = sorted(set(union))
        xs = set(self.X)
        self.peer_excl = sorted(set(self.U) - xs)
        # PRF caches
        self.prf_peer_excl = []
        self.prf_own_add = []
        self.prf_peer_del = []
        self.prf_D_own = []

    def __repr__(self):
        return f"Party({self.name}, |X|={len(self.X)}, |U|={len(self.U)})"


def UpdateRound(p0: PartyState, p1: PartyState,
                X_plus: list, X_minus: list,
                Y_plus: list, Y_minus: list):
    """Execute one update round. Returns (U_p0, U_p1)."""

    # ═════ Preprocess ═════
    p0_query = p0.peer_excl + X_plus
    p1_query = p1.peer_excl + Y_plus

    # MROPRF: P0 receives F_k1 of its queries; P1 receives F_k0 of its queries
    p0_vals = [ComputeSinglePRF(x, k1) for x in p0_query]
    p1_vals = [ComputeSinglePRF(x, k0) for x in p1_query]

    # Raise to own key → double-keyed F values
    n_pe_p0 = len(p0.peer_excl)
    p0.prf_peer_excl = [RaiseToKey(v, k0) for v in p0_vals[:n_pe_p0]]
    p0.prf_own_add = [RaiseToKey(v, k0) for v in p0_vals[n_pe_p0:]]

    n_pe_p1 = len(p1.peer_excl)
    p1.prf_peer_excl = [RaiseToKey(v, k1) for v in p1_vals[:n_pe_p1]]
    p1.prf_own_add = [RaiseToKey(v, k1) for v in p1_vals[n_pe_p1:]]

    # Verify commutativity on common elements
    comm = ToSet(p0.peer_excl) & ToSet(p1.peer_excl)
    for x in comm:
        f0 = p0.prf_peer_excl[p0.peer_excl.index(x)]
        f1 = p1.prf_peer_excl[p1.peer_excl.index(x)]
        assert f0 == f1, f"Commutativity FAIL at x={x}"

    # ═════ Deletion ═════
    # Exchange single-keyed deletion PRFs
    fk0_Xm = [ComputeSinglePRF(x, k0) for x in X_minus]
    fk1_Ym = [ComputeSinglePRF(y, k1) for y in Y_minus]

    # Each raises peer's to own key
    p0.prf_peer_del = [RaiseToKey(v, k0) for v in fk1_Ym]  # F(Y_i^-)
    p1.prf_peer_del = [RaiseToKey(v, k1) for v in fk0_Xm]  # F(X_i^-)

    # D_X = peer_excl ∩ Y_i^-  (in F-space)
    p0.prf_D_own = PRF_Intersect(p0.prf_peer_excl, p0.prf_peer_del)
    # D_Y = peer_excl ∩ X_i^-
    p1.prf_D_own = PRF_Intersect(p1.prf_peer_excl, p1.prf_peer_del)

    # Verify: P0 knows D_X plaintext (elements in peer_excl)
    d_x_expected = ToSet(p0.peer_excl) & ToSet(Y_minus)
    d_y_expected = ToSet(p1.peer_excl) & ToSet(X_minus)

    # PSI(F(Y_i^-), F(X_i^-)) → F(X_i^- ∩ Y_i^-)
    p0_psi = sorted(set(HashPRFToUint128(v) for v in p0.prf_peer_del))
    p1_psi = sorted(set(HashPRFToUint128(v) for v in p1.prf_peer_del))
    psi_hashes = sorted(set(p0_psi) & set(p1_psi))
    lookup_p0 = {HashPRFToUint128(v): v for v in p0.prf_peer_del}
    lookup_p1 = {HashPRFToUint128(v): v for v in p1.prf_peer_del}
    xi_cap_yi_p0 = [lookup_p0[h] for h in psi_hashes if h in lookup_p0]
    xi_cap_yi_p1 = [lookup_p1[h] for h in psi_hashes if h in lookup_p1]
    assert set(xi_cap_yi_p0) == set(xi_cap_yi_p1), "PSI mismatch"

    # Exchange F(D_X) ↔ F(D_Y)
    prf_DY = p1.prf_D_own
    prf_DX = p0.prf_D_own

    # Build F(U_i^-)
    u_minus = ToSet(p0.prf_D_own) | ToSet(prf_DY) | ToSet(xi_cap_yi_p0)
    u_minus_check = ToSet(p1.prf_D_own) | ToSet(prf_DX) | ToSet(xi_cap_yi_p1)
    assert u_minus == u_minus_check, f"U_i^- mismatch"

    # ═════ Addition ═════
    # P1 → P0: F_{k1}(U_{i-1})
    fk1_Uprev = [ComputeSinglePRF(u, k1) for u in p1.U]
    # P0 raises with k0
    f_Uprev = [RaiseToKey(v, k0) for v in fk1_Uprev]

    # Remove U_i^-, add X_i^+
    f_partial = [v for v in f_Uprev if v not in u_minus]
    f_partial.extend(p0.prf_own_add)

    # P1 receives, adds Y_i^+, strips k1 → F_{k0}(U_i)
    f_partial_p1 = list(f_partial)
    f_partial_p1.extend(p1.prf_own_add)
    fk0_Ui = [StripKey(v, k1_inv) for v in f_partial_p1]

    # P0 strips k0 → H(U_i), maps to plaintext
    H_Ui = [StripKey(v, k0_inv) for v in fk0_Ui]

    # P0 lookup: H(x) → x
    htab = {HashToCurve(u): u for u in p0.U}
    for x in X_plus:
        htab[HashToCurve(x)] = x

    Ui_new_p0 = []
    unmapped = []
    for h in H_Ui:
        if h in htab:
            Ui_new_p0.append(htab[h])
        else:
            unmapped.append(h)

    # P1 resolves unmapped
    htab_p1 = {HashToCurve(y): y for y in Y_plus}
    for y in p1.X:
        htab_p1[HashToCurve(y)] = y

    peer_pl = []
    for h in unmapped:
        if h in htab_p1:
            peer_pl.append(htab_p1[h])
        # else: collision or element from third source, shouldn't happen

    Ui_new = sorted(Ui_new_p0 + peer_pl)

    # ═════ Update State ═════
    # P0
    xs = set(p0.X)
    for x in X_minus: xs.discard(x)
    for x in X_plus: xs.add(x)
    p0.X = sorted(xs)
    p0.U = Ui_new
    p0.peer_excl = sorted(set(p0.U) - set(p0.X))

    # P1
    ys = set(p1.X)
    for y in Y_minus: ys.discard(y)
    for y in Y_plus: ys.add(y)
    p1.X = sorted(ys)
    p1.U = list(Ui_new)  # P1 receives final U_i from P0
    p1.peer_excl = sorted(set(p1.U) - set(p1.X))

    return Ui_new, Ui_new


# ── Test harness ────────────────────────────────────────────────────
def make_set(base, n):
    """Generate n deterministic uint128-like values."""
    out = []
    for i in range(n):
        raw = hashlib.blake2b(f"{base}_{i}".encode(), digest_size=16).digest()
        out.append(int.from_bytes(raw, 'little'))
    return out


def run_test(n=20, add_n=4, sub_n=2, rounds=3, verbose=True):
    """Correctness test with small sets."""

    X = make_set(0, n)
    Y = make_set(n // 2, n)

    X_cur = set(X)
    Y_cur = set(Y)
    U_gt = sorted(X_cur | Y_cur)

    if verbose:
        print(f"=== UPSU Simulation ===")
        print(f"|X|={len(X)} |Y|={len(Y)} |U0|={len(U_gt)}")

    # Init
    p0 = PartyState("P0", X, U_gt)
    p1 = PartyState("P1", Y, U_gt)

    assert sorted(p0.U) == U_gt
    assert sorted(p1.U) == U_gt
    print(f"Init: CORRECT ({len(U_gt)} elements)")

    all_ok = True
    for r in range(rounds):
        add_base = (r + 2) * n + add_n
        sub_off = (r * sub_n) % n

        X_plus = make_set(add_base, add_n)
        X_minus = [make_set(sub_off + i, 1)[0] for i in range(sub_n)]

        y_add_base = add_base + add_n
        Y_plus = make_set(y_add_base, add_n)
        Y_minus = []
        for i in range(sub_n):
            idx = n // 2 + sub_off + i
            if idx < n // 2 + n:
                Y_minus.append(make_set(idx, 1)[0])

        U_p0, U_p1 = UpdateRound(p0, p1, X_plus, X_minus, Y_plus, Y_minus)

        # Update ground truth
        for x in X_minus: X_cur.discard(x)
        for y in Y_minus: Y_cur.discard(y)
        for x in X_plus: X_cur.add(x)
        for y in Y_plus: Y_cur.add(y)
        U_gt_new = sorted(X_cur | Y_cur)

        ok0 = (sorted(U_p0) == U_gt_new)
        ok1 = (sorted(U_p1) == U_gt_new)

        status = "OK" if (ok0 and ok1) else "FAIL"
        if not ok0 or not ok1:
            all_ok = False
            if not ok0:
                missing = ToSet(U_gt_new) - ToSet(U_p0)
                extra = ToSet(U_p0) - ToSet(U_gt_new)
                print(f"  Round {r+1} P0: missing={len(missing)} extra={len(extra)}")
            if not ok1:
                missing = ToSet(U_gt_new) - ToSet(U_p1)
                extra = ToSet(U_p1) - ToSet(U_gt_new)
                print(f"  Round {r+1} P1: missing={len(missing)} extra={len(extra)}")

        assert sorted(p0.U) == sorted(p1.U), \
            f"Round {r+1}: P0/P1 diverged"

        print(f"  Round {r+1}: {status} |U|={len(U_gt_new)} "
              f"(+{add_n*2} -~{sub_n*2})")

    if all_ok:
        print(f"\nAll {rounds} rounds PASSED.")
    else:
        print(f"\nFAILED!")

    return all_ok


if __name__ == '__main__':
    verbose = '--quiet' not in sys.argv
    success = run_test(n=20, add_n=5, sub_n=3, rounds=5, verbose=verbose)
    sys.exit(0 if success else 1)
