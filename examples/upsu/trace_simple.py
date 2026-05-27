"""UPSU Protocol ? ultra-simple trace with small readable numbers.

Uses a tiny 32-bit safe prime so all PRF values fit in 64-bit integers.
Elements are plain integers {0..N}.
"""

import hashlib
import random

# -- Tiny safe prime (~31 bit) for readable numbers -----------------
# p = 2q+1 where q is also prime. q ~ 30 bits, p ~ 31 bits.
# This makes all modular exponentiations produce ~9-digit numbers.
SCALAR_ORDER = 902054171       # a real 30-bit prime q
FIELD_MODULUS = 1804108343      # p = 2q+1, a real safe prime (31-bit)

# Quick sanity check
assert pow(2, FIELD_MODULUS - 1, FIELD_MODULUS) == 1, "FIELD_MODULUS not prime"
assert (FIELD_MODULUS - 1) % SCALAR_ORDER == 0, "not a safe prime (p != 2q+1)"

# Tiny keys for readability
k0 = 12345
k1 = 67890
k0_inv = pow(k0, -1, SCALAR_ORDER)
k1_inv = pow(k1, -1, SCALAR_ORDER)

print(f"FIELD_MODULUS p = {FIELD_MODULUS} (safe prime)")
print(f"SCALAR_ORDER q = {SCALAR_ORDER} (group order, (p-1)/2)")
print(f"k0 = {k0},  k1 = {k1}")
print(f"k0_inv = {k0_inv},  k1_inv = {k1_inv}")
print(f"Verify: k0 * k0_inv mod q = {(k0 * k0_inv) % SCALAR_ORDER}")  # must be 1
print(f"Verify: k1 * k1_inv mod q = {(k1 * k1_inv) % SCALAR_ORDER}")  # must be 1
print()


# -- PRF primitives -------------------------------------------------
def H(x: int) -> int:
    """Hash to subgroup: sha256, square mod p -> quadratic residue (order q)."""
    raw = hashlib.sha256(str(x).encode()).digest()
    h = int.from_bytes(raw[:8], 'little') % FIELD_MODULUS
    return pow(h, 2, FIELD_MODULUS)


def F_sk(x: int, sk: int) -> int:
    """Single-keyed PRF: H(x)^sk mod p."""
    return pow(H(x), sk, FIELD_MODULUS)


def raise_k(v: int, sk: int) -> int:
    """Raise: v^sk mod p."""
    return pow(v, sk, FIELD_MODULUS)


def strip_k(v: int, skinv: int) -> int:
    """Strip: v^{sk^{-1}} mod p."""
    return pow(v, skinv, FIELD_MODULUS)


# -- Verify DH properties -------------------------------------------
test_x = 42
h42 = H(test_x)
# single-keyed
f_k0 = F_sk(test_x, k0)
f_k1 = F_sk(test_x, k1)
# double-keyed (commutative)
f_k01 = raise_k(f_k1, k0)    # (H^k1)^k0 = H^{k1*k0}
f_k10 = raise_k(f_k0, k1)    # (H^k0)^k1 = H^{k0*k1}
# strip back
strip_back = strip_k(strip_k(f_k01, k1_inv), k0_inv)

print("=== DH PRF Property Check ===")
print(f"  x = {test_x}")
print(f"  H(x) = {h42}")
print(f"  F_k0(x) = H(x)^k0 = {f_k0}")
print(f"  F_k1(x) = H(x)^k1 = {f_k1}")
print(f"  F_k01(x) = raise(F_k1, k0) = H^{k0*k1} = {f_k01}")
print(f"  F_k10(x) = raise(F_k0, k1) = H^{k1*k0} = {f_k10}")
print(f"  Commutative? {f_k01 == f_k10}")
print(f"  Strip both keys back: {strip_back}")
print(f"  Equals H(x)? {strip_back == h42}")
print()


# ================== THE EXAMPLE =====================================

# X = {10, 20, 30, 40, 50, 60}
# Y = {40, 50, 60, 70, 80, 90}
# Overlap = {40, 50, 60}

# Round 1:
#   X adds {100, 110}, deletes {20}
#   Y adds {120, 130}, deletes {80}

X = [10, 20, 30, 40, 50, 60]
Y = [40, 50, 60, 70, 80, 90]

X_plus  = [100, 110]
X_minus = [20]
Y_plus  = [120, 130]
Y_minus = [80]

print("=" * 70)
print("|  CONCRETE EXAMPLE")
print("=" * 70)
print()
print(f"  X = {X}")
print(f"  Y = {Y}")
print(f"  X && Y = {sorted(set(X) & set(Y))}")
print()
print(f"  Round 1:")
print(f"    X+ = {X_plus}  (P0 adds)")
print(f"    X- = {X_minus}    (P0 deletes)")
print(f"    Y+ = {Y_plus}  (P1 adds)")
print(f"    Y- = {Y_minus}    (P1 deletes)")
print()

# -- Init --
print("-" * 50)
print("INIT: PSU -> both get U0 = X \/ Y")
print("-" * 50)

U0 = sorted(set(X) | set(Y))
print(f"  U0 = {U0}")
print(f"  |U0| = {len(U0)}")
print()

# peer_excl
peer_excl_p0 = sorted(set(U0) - set(X))
peer_excl_p1 = sorted(set(U0) - set(Y))
print(f"  P0.X = {sorted(X)}")
print(f"  P0.peer_excl = U0 \\ X = {peer_excl_p0}")
print(f"    (P0 knows: these are Y's exclusive elements)")
print()
print(f"  P1.X = {sorted(Y)}")
print(f"  P1.peer_excl = U0 \\ Y = {peer_excl_p1}")
print(f"    (P1 knows: these are P0's exclusive elements)")

# =========== Preprocess ===========
print()
print("-" * 50)
print("PREPROCESS (MROPRF)")
print("-" * 50)

p0_query = peer_excl_p0 + X_plus
p1_query = peer_excl_p1 + Y_plus
print(f"  P0 queries: peer_excl ({peer_excl_p0}) + X+ ({X_plus})")
print(f"    = {p0_query}")
print(f"  P1 queries: peer_excl ({peer_excl_p1}) + Y+ ({Y_plus})")
print(f"    = {p1_query}")
print()

# MROPRF results
p0_fk1 = {x: F_sk(x, k1) for x in p0_query}  # P0 gets F_k1 of its queries
p1_fk0 = {x: F_sk(x, k0) for x in p1_query}  # P1 gets F_k0 of its queries

print(f"  P0 receives F_k1 of each query from P1:")
for x in p0_query:
    print(f"    F_k1({x:>3}) = ...{p0_fk1[x] % 1000000:0>6}")
print(f"  P1 receives F_k0 of each query from P0:")
for x in p1_query:
    print(f"    F_k0({x:>3}) = ...{p1_fk0[x] % 1000000:0>6}")
print()

# Raise to own key -> double-keyed
p0_F = {}  # P0's double-keyed PRF lookup: element -> F(x)
for x in peer_excl_p0:
    p0_F[x] = raise_k(p0_fk1[x], k0)
for x in X_plus:
    p0_F[x] = raise_k(p0_fk1[x], k0)

p1_F = {}
for x in peer_excl_p1:
    p1_F[x] = raise_k(p1_fk0[x], k1)
for x in Y_plus:
    p1_F[x] = raise_k(p1_fk0[x], k1)

print(f"  P0 raises with k0 -> double-keyed F(x) = F_{{k0,k1}}(x):")
for x in p0_query:
    tag = "peer_excl" if x in peer_excl_p0 else "X+"
    print(f"    F({x:>3}) [{tag:>10}] = {p0_F[x]}")
print(f"  P1 raises with k1 -> double-keyed F(x):")
for x in p1_query:
    tag = "peer_excl" if x in peer_excl_p1 else "Y+"
    print(f"    F({x:>3}) [{tag:>10}] = {p1_F[x]}")
print()

# Verify commutativity on overlap
overlap = set(peer_excl_p0) & set(peer_excl_p1)
if overlap:
    print(f"  Commutativity check on X/\Y elements ({sorted(overlap)}):")
    for x in sorted(overlap)[:3]:
        f0 = p0_F[x]  # raise_k(F_k1(x), k0)
        f1 = p1_F[x]  # raise_k(F_k0(x), k1)
        print(f"    F_k01({x}) = P0: {f0}")
        print(f"    F_k10({x}) = P1: {f1}")
        print(f"    Match: {f0 == f1}")
    print()

# =========== Deletion ===========
print("-" * 50)
print("DELETION")
print("-" * 50)

# Step 1-2: Exchange single-keyed deletion PRFs
p0_fk0_Xm = {x: F_sk(x, k0) for x in X_minus}
p1_fk1_Ym = {y: F_sk(y, k1) for y in Y_minus}

print(f"  Step 1: P0 -> P1  F_k0(X-) = F_k0({X_minus})")
for x in X_minus:
    print(f"    F_k0({x}) = {p0_fk0_Xm[x]}")
print(f"  Step 2: P1 -> P0  F_k1(Y-) = F_k1({Y_minus})")
for y in Y_minus:
    print(f"    F_k1({y}) = {p1_fk1_Ym[y]}")
print()

# Raise to double-keyed
p0_F_Ym = {y: raise_k(p1_fk1_Ym[y], k0) for y in Y_minus}  # F(Y-) from P0's view
p1_F_Xm = {x: raise_k(p0_fk0_Xm[x], k1) for x in X_minus}  # F(X-) from P1's view

print(f"  P0 raises F_k1(Y-) with k0 -> F(Y-):")
for y in Y_minus:
    print(f"    F({y}) = {p0_F_Ym[y]}")
print(f"  P1 raises F_k0(X-) with k1 -> F(X-):")
for x in X_minus:
    print(f"    F({x}) = {p1_F_Xm[x]}")
print()

# D_X and D_Y computation
p0_prf_DX = []
for y in Y_minus:
    if p0_F_Ym[y] in [p0_F[x] for x in peer_excl_p0]:
        p0_prf_DX.append(p0_F_Ym[y])
        # Find plaintext
        for px in peer_excl_p0:
            if p0_F[px] == p0_F_Ym[y]:
                print(f"  D_X: F({y}) matches F(peer_excl:{px}) -> P0 knows {y} is deleted from Y")
                break

p1_prf_DY = []
for x in X_minus:
    if p1_F_Xm[x] in [p1_F[px] for px in peer_excl_p1]:
        p1_prf_DY.append(p1_F_Xm[x])
        for px in peer_excl_p1:
            if p1_F[px] == p1_F_Xm[x]:
                print(f"  D_Y: F({x}) matches F(peer_excl:{px}) -> P1 knows {x} is deleted from X")
                break
print()

# PSI for X- /\ Y-
# Hash to uint128 (simulated as just the value mod something small for readability)
print(f"  Step 4: PSI between Blake3(F(Y-)) and Blake3(F(X-))")
p0_psi_vals = sorted(set(p0_F_Ym.values()))
p1_psi_vals = sorted(set(p1_F_Xm.values()))
psi_common = set(p0_psi_vals) & set(p1_psi_vals)
print(f"    P0 inputs: F(Y-) = {p0_psi_vals}")
print(f"    P1 inputs: F(X-) = {p1_psi_vals}")
print(f"    Intersection (in F-space): {sorted(psi_common) if psi_common else '(none)'}")
print(f"    -> X- /\ Y- = {sorted(set(X_minus) & set(Y_minus))}")
print(f"    Neither can map these! P0 only has peer_excl mapping, P1 same.")
print()

# Exchange D_X ? D_Y
print(f"  Step 5: Exchange F(D_X) ? F(D_Y)")
p0_gets_DY = p1_prf_DY  # P0 receives F(D_Y) from P1
p1_gets_DX = p0_prf_DX  # P1 receives F(D_X) from P0
print(f"    P0 -> P1: F(D_X) = {p0_prf_DX}")
print(f"    P1 -> P0: F(D_Y) = {p1_prf_DY}")

# Build U-
u_minus_set = set(p0_prf_DX) | set(p0_gets_DY) | psi_common
print(f"    U- = D_X + D_Y + (X-/\Y-) = {sorted(u_minus_set)}")
print(f"    |U-| = {len(u_minus_set)}  (to be removed)")
print()

# =========== Addition ===========
print("-" * 50)
print("ADDITION (Blind)")
print("-" * 50)

# P1 -> P0: F_k1(U0)
p1_Fk1_U0 = {u: F_sk(u, k1) for u in U0}
print(f"  Step 1: P1 -> P0  F_k1(U0),  |U0| = {len(U0)}")
for u in U0:
    print(f"    F_k1({u:>3}) = {p1_Fk1_U0[u]}")

# P0 raises with k0
p0_F_U0 = {u: raise_k(p1_Fk1_U0[u], k0) for u in U0}
print(f"  P0 raises with k0 -> F(U0):")
for u in U0:
    print(f"    F({u:>3}) = {p0_F_U0[u]}")

# Remove U-, add X+
p0_partial = {u: p0_F_U0[u] for u in U0 if p0_F_U0[u] not in u_minus_set}
print()
print(f"  Step 2: P0 removes U- from F(U0)")
removed = [u for u in U0 if p0_F_U0[u] in u_minus_set]
print(f"    Removed (in U-): {removed}")
print(f"    Remaining: {sorted(p0_partial.keys())}")
print(f"    Their F values: {sorted(p0_partial.values())}")

# Add X+
for x in X_plus:
    p0_partial[x] = p0_F[x]  # F(X+) from preprocess
print(f"    Add X+ = {X_plus}:")
for x in X_plus:
    print(f"      F({x}) = {p0_F[x]}")

print(f"    -> Send to P1: {sorted(p0_partial.values())}")
print(f"      (P1 sees F-values only, cannot distinguish X+ from surviving U0 elements)")

# P1 adds Y+, strips k1
p1_partial = dict(p0_partial)
for y in Y_plus:
    p1_partial[y] = p1_F[y]  # F(Y+) from preprocess
print()
print(f"  Step 3: P1 adds Y+ = {Y_plus}:")
for y in Y_plus:
    print(f"    F({y}) = {p1_F[y]}")
print(f"    All F-values: {sorted(p1_partial.values())}")

# Strip k1: F_{k0,k1}(z)^{k1^{-1}} = F_{k0}(z)
p1_Fk0_U1 = {}
for elem, fval in p1_partial.items():
    p1_Fk0_U1[elem] = strip_k(fval, k1_inv)
print()
print(f"  Step 4: P1 strips k1 -> F_k0(U1):")
for elem, fk0 in sorted(p1_Fk0_U1.items()):
    print(f"    F_k0({elem:>3}) = {fk0}")

# P0 strips k0 -> H(U1)
print()
print(f"  Step 5: P0 strips k0 -> H(U1):")
p0_H = {}
for elem, fk0 in p1_Fk0_U1.items():
    p0_H[elem] = strip_k(fk0, k0_inv)
    print(f"    H({elem:>3}) = {p0_H[elem]}")

# P0 maps H(z) to known plaintext
print()
print(f"  Step 6: P0 maps H(z) -> plaintext")
print(f"    P0's lookup: H(U0) \/ H(X+)")
p0_htab = {}
for u in U0:
    p0_htab[H(u)] = u
for x in X_plus:
    p0_htab[H(x)] = x

mapped = {}
unmapped = {}
for elem, hval in p0_H.items():
    if hval in p0_htab:
        mapped[hval] = p0_htab[hval]
        print(f"      H({elem:>3}) -> {p0_htab[hval]}  (known)")
    else:
        unmapped[hval] = elem
        print(f"      H({elem:>3}) -> ???  (unknown -> P1)")

# P1 resolves unmapped
print()
print(f"  Step 7: P1 resolves unmapped")
print(f"    P1's lookup: H(Y0) \/ H(Y+)")
p1_htab = {}
for y in Y:
    p1_htab[H(y)] = y
for y in Y_plus:
    p1_htab[H(y)] = y

resolved = {}
for hval in unmapped:
    if hval in p1_htab:
        resolved[hval] = p1_htab[hval]
        print(f"      H -> {p1_htab[hval]}  (from Y or Y+)")

U1 = sorted(list(mapped.values()) + list(resolved.values()))
print()

# =========== Result ===========
print("-" * 50)
print("RESULT")
print("-" * 50)

# Ground truth
U1_gt = sorted((set(X) - set(X_minus)) | (set(Y) - set(Y_minus)) | set(X_plus) | set(Y_plus))
print(f"  Protocol output: U1 = {U1}")
print(f"  Ground truth:    U1 = {U1_gt}")
print(f"  Correct: {U1 == U1_gt}")
print()

# Show what happened to each element
print("  Element lifecycle:")
all_elements = sorted(set(X) | set(Y) | set(X_plus) | set(Y_plus))
for e in all_elements:
    in_U0 = e in set(U0)
    in_U1 = e in set(U1)
    deleted = in_U0 and not in_U1
    added = not in_U0 and in_U1
    survived = in_U0 and in_U1

    parts = []
    if e in X_minus: parts.append("X- (P0 tries to delete)")
    if e in Y_minus: parts.append("Y- (P1 tries to delete)")
    if e in X_plus: parts.append("X+ (P0 adds)")
    if e in Y_plus: parts.append("Y+ (P1 adds)")
    if e in X and e not in X_minus: parts.append("surviving X")
    if e in Y and e not in Y_minus: parts.append("surviving Y")

    action = "DELETED" if deleted else ("ADDED" if added else "KEPT")
    print(f"  {e:>4}: {action:<8}  [{', '.join(parts)}]")

print()
print("  Summary:")
print(f"    |U0| = {len(U0)},  removed = {len(u_minus_set)},  added = {len(X_plus) + len(Y_plus)}")
print(f"    |U1| = {len(U1)}")
print(f"    Expected = {len(U1_gt)}")
