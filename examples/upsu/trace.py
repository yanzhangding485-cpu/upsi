"""Detailed single-round protocol trace for UPSU."""
import hashlib
import sys
sys.path.insert(0, 'C:/Users/joel13/upsi/examples/upsu')
from simulate import *

# ── Tiny example: |X|=|Y|=5, add=2, del=1, 1 round ──

# Fix keys for reproducibility
global k0, k1, k0_inv, k1_inv
k0 = 123456789
k1 = 987654321
k0_inv = pow(k0, -1, SCALAR_ORDER)
k1_inv = pow(k1, -1, SCALAR_ORDER)

n, add_n, sub_n = 5, 2, 1

X = make_set(0, n)
Y = make_set(n // 2, n)

def short(x):
    """Short hex representation of an element."""
    return hashlib.sha256(str(x).encode()).hexdigest()[:6]

print('=' * 60)
print('UPSU Protocol — Concrete Trace')
print('=' * 60)
print()
print(f'Parameters: |X|={n}, |Y|={n}, |X+|={add_n}, |X-|={sub_n}')
print(f'Scalar order bit length: {SCALAR_ORDER.bit_length()}')
print()
print(f'X = {{x0..x{n-1}}}')
for i, x in enumerate(X):
    print(f'  x{i} = {short(x)}')
print(f'Y = {{y0..y{n-1}}}')
for i, y in enumerate(Y):
    print(f'  y{i} = {short(y)}')

xs = set(X); ys = set(Y)
inter = xs & ys
print()
print(f'Overlap: |X cap Y| = {len(inter)}')
print(f'X only (X\\Y): {len(xs - ys)} elements')
print(f'Y only (Y\\X): {len(ys - xs)} elements')
print()

# ─── Init ───
print('─' * 40)
print('INIT PHASE')
print('─' * 40)
U = sorted(xs | ys)
p0 = PartyState('P0', X, U)
p1 = PartyState('P1', Y, U)
print(f'U0 = X union Y = {len(U)} elements')
print(f'After PSU: both parties hold U0')
print(f'P0.peer_excl = U0 \\ X = {len(p0.peer_excl)} elements')
print(f'  (These are Y\\X — P0 knows these belong to P1)')
print(f'P1.peer_excl = U0 \\ Y = {len(p1.peer_excl)} elements')
print(f'  (These are X\\Y — P1 knows these belong to P0)')
print()

# ─── Round 1 data ───
add_base = (0 + 2) * n + add_n
sub_off = (0 * sub_n) % n
X_plus = make_set(add_base, add_n)
X_minus = [make_set(sub_off + i, 1)[0] for i in range(sub_n)]
Y_plus = make_set(add_base + add_n, add_n)
Y_minus = [make_set(n//2 + sub_off + i, 1)[0] for i in range(sub_n)]

print('─' * 40)
print('ROUND 1 — Update Data')
print('─' * 40)
print(f'X+ = new elements P0 wants to add:')
for i, x in enumerate(X_plus):
    print(f'  x+{i} = {short(x)}')
print(f'X- = elements P0 wants to delete:')
for i, x in enumerate(X_minus):
    print(f'  x-{i} = {short(x)}  (was in X)')
print(f'Y+ = new elements P1 wants to add:')
for i, y in enumerate(Y_plus):
    print(f'  y+{i} = {short(y)}')
print(f'Y- = elements P1 wants to delete:')
for i, y in enumerate(Y_minus):
    in_Y = y in ys
    print(f'  y-{i} = {short(y)}  (in Y: {in_Y})')
print()

# ═══════════ Preprocess ═══════════
print('─' * 40)
print('PREPROCESS PHASE (MROPRF)')
print('─' * 40)
p0_query = p0.peer_excl + X_plus
p1_query = p1.peer_excl + Y_plus
print(f'P0 queries peer_excl + X+ = {len(p0.peer_excl)} + {len(X_plus)} = {len(p0_query)} items')
print(f'  As MROPRF Receiver: gets F_{{k1}}(query) from P1')
print(f'P1 queries peer_excl + Y+ = {len(p1.peer_excl)} + {len(Y_plus)} = {len(p1_query)} items')
print(f'  As MROPRF Receiver: gets F_{{k0}}(query) from P0')

p0_vals = [ComputeSinglePRF(x, k1) for x in p0_query]
p1_vals = [ComputeSinglePRF(x, k0) for x in p1_query]

# Verify commutativity on common elements
common = set(p0.peer_excl) & set(p1.peer_excl)
print()
print('Commutativity check on X cap Y elements:')
for x in list(common)[:2]:
    idx0 = p0.peer_excl.index(x)
    idx1 = p1.peer_excl.index(x)
    f0 = RaiseToKey(p0_vals[idx0], k0)  # F_{k0,k1}(x)
    f1 = RaiseToKey(p1_vals[idx1], k1)  # F_{k1,k0}(x)
    print(f'  F_{{k0,k1}}({short(x)}) = F_{{k1,k0}}({short(x)}) ? {f0 == f1}')

n_pe0 = len(p0.peer_excl)
p0.prf_peer_excl = [RaiseToKey(v, k0) for v in p0_vals[:n_pe0]]
p0.prf_own_add = [RaiseToKey(v, k0) for v in p0_vals[n_pe0:]]
n_pe1 = len(p1.peer_excl)
p1.prf_peer_excl = [RaiseToKey(v, k1) for v in p1_vals[:n_pe1]]
p1.prf_own_add = [RaiseToKey(v, k1) for v in p1_vals[n_pe1:]]

print()
print(f'P0 raises F_{{k1}}(output) with k0:')
print(f'  prf_peer_excl = F(peer_excl) = {len(p0.prf_peer_excl)} double-keyed values')
print(f'  prf_own_add = F(X+) = {len(p0.prf_own_add)} double-keyed values')
print(f'P1 raises F_{{k0}}(output) with k1:')
print(f'  prf_peer_excl = F(peer_excl) = {len(p1.prf_peer_excl)} double-keyed values')
print(f'  prf_own_add = F(Y+) = {len(p1.prf_own_add)} double-keyed values')
print()

# ═══════════ Deletion ═══════════
print('─' * 40)
print('DELETION PHASE')
print('─' * 40)

# Step 1-2: Exchange single-keyed deletion PRFs
fk0_Xm = [ComputeSinglePRF(x, k0) for x in X_minus]
fk1_Ym = [ComputeSinglePRF(y, k1) for y in Y_minus]
print(f'Step 1: P0 sends F_{{k0}}(X-) to P1 ({len(fk0_Xm)} values)')
for i, v in enumerate(fk0_Xm):
    print(f'  F_{{k0}}(x-{i}) = ...{v % 1000000}')
print(f'Step 2: P1 sends F_{{k1}}(Y-) to P0 ({len(fk1_Ym)} values)')
for i, v in enumerate(fk1_Ym):
    print(f'  F_{{k1}}(y-{i}) = ...{v % 1000000}')

# Step 3: Each raises to own key → double-keyed
p0.prf_peer_del = [RaiseToKey(v, k0) for v in fk1_Ym]
p1.prf_peer_del = [RaiseToKey(v, k1) for v in fk0_Xm]
print(f'P0 raises F_{{k1}}(Y-) with k0 -> F(Y-) = {len(p0.prf_peer_del)} values')
print(f'P1 raises F_{{k0}}(X-) with k1 -> F(X-) = {len(p1.prf_peer_del)} values')

# Step 4: D_X, D_Y
p0.prf_D_own = PRF_Intersect(p0.prf_peer_excl, p0.prf_peer_del)
p1.prf_D_own = PRF_Intersect(p1.prf_peer_excl, p1.prf_peer_del)
print()
print(f'Step 3: D_X = F(peer_excl) cap F(Y-) = {len(p0.prf_D_own)} values')
print(f'  In plaintext: (Y\\X) cap Y-')
print(f'  P0 can MAP D_X: YES (has preprocess mapping for peer_excl)')
print(f'Step 3: D_Y = F(peer_excl) cap F(X-) = {len(p1.prf_D_own)} values')
print(f'  In plaintext: (X\\Y) cap X-')
print(f'  P1 can MAP D_Y: YES (has preprocess mapping for peer_excl)')

# Step 5: PSI
p0_psi = sorted(set(HashPRFToUint128(v) for v in p0.prf_peer_del))
p1_psi = sorted(set(HashPRFToUint128(v) for v in p1.prf_peer_del))
psi_hashes = sorted(set(p0_psi) & set(p1_psi))
lookup_p0 = {HashPRFToUint128(v): v for v in p0.prf_peer_del}
lookup_p1 = {HashPRFToUint128(v): v for v in p1.prf_peer_del}
xi_cap_yi_p0 = [lookup_p0[h] for h in psi_hashes if h in lookup_p0]
xi_cap_yi_p1 = [lookup_p1[h] for h in psi_hashes if h in lookup_p1]
print()
print(f'Step 4: PSI between Blake3(F(Y-)) and Blake3(F(X-))')
print(f'  P0 inputs: {len(p0_psi)} hashes')
print(f'  P1 inputs: {len(p1_psi)} hashes')
print(f'  Result: {len(psi_hashes)} values = F(X- cap Y-)')
print(f'  Neither party can MAP X- cap Y-: CORRECT')
print(f'    P0 has F(Y-) but only peer_excl mapping (not X- elements)')
print(f'    P1 has F(X-) but only peer_excl mapping (not Y- elements)')

# Step 6: Exchange D
prf_DY = p1.prf_D_own
prf_DX = p0.prf_D_own
print()
print(f'Step 5: Exchange F(D_X) <-> F(D_Y)')
print(f'  P0 -> P1: F(D_X) = {len(prf_DX)} values')
print(f'  P1 -> P0: F(D_Y) = {len(prf_DY)} values')

# Build U_i^-
u_minus = set(p0.prf_D_own) | set(prf_DY) | set(xi_cap_yi_p0)
print()
print(f'Step 6: U- = D_X ({len(p0.prf_D_own)}) + D_Y ({len(prf_DY)}) + (X-cap-Y-) ({len(xi_cap_yi_p0)})')
print(f'  Total: {len(u_minus)} F-values to remove')
print()

# ═══════════ Addition ═══════════
print('─' * 40)
print('ADDITION PHASE (Blind)')
print('─' * 40)

# P1 sends F_{k1}(U0)
fk1_Uprev = [ComputeSinglePRF(u, k1) for u in p1.U]
f_Uprev = [RaiseToKey(v, k0) for v in fk1_Uprev]
print(f'Step 1: P1 -> P0: F_{{k1}}(U0) = {len(fk1_Uprev)} values')
print(f'  P0 raises with k0 -> F(U0) = {len(f_Uprev)} values')

f_partial = [v for v in f_Uprev if v not in u_minus]
print(f'Step 2: P0 removes U- from F(U0)')
print(f'  F(U0) = {len(f_Uprev)}, remove {len(u_minus)} -> {len(f_partial)} remaining')
f_partial.extend(p0.prf_own_add)
print(f'  Add F(X+) = {len(p0.prf_own_add)} -> {len(f_partial)} total')
print(f'  P0 -> P1: F(U0 \\ U- union X+)')

f_partial_p1 = list(f_partial)
f_partial_p1.extend(p1.prf_own_add)
print(f'Step 3: P1 receives, adds F(Y+) = {len(p1.prf_own_add)} -> {len(f_partial_p1)} total')
fk0_Ui = [StripKey(v, k1_inv) for v in f_partial_p1]
print(f'Step 4: P1 strips k1 -> F_{{k0}}(U1) = {len(fk0_Ui)} values')
print(f'  For each z in U1: F_{{k0,k1}}(z)^{{k1^-1}} = F_{{k0}}(z)')

H_Ui = [StripKey(v, k0_inv) for v in fk0_Ui]
print(f'Step 5: P1 -> P0: F_{{k0}}(U1)')
print(f'  P0 strips k0 -> H(U1) = {len(H_Ui)} values')
print(f'  For each z in U1: F_{{k0}}(z)^{{k0^-1}} = H(z)')

# Map to plaintext
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

print(f'Step 6: P0 maps H(z) to plaintext')
print(f'  Lookup: U0 ({len(p0.U)}) + X+ ({len(X_plus)}) = {len(htab)} entries')
print(f'  Mapped: {len(Ui_new_p0)} elements (from U0\\U- and X+)')
print(f'  Unmapped: {len(unmapped)} elements (Y+ and surviving Y\\X)')

htab_p1 = {HashToCurve(y): y for y in Y_plus}
for y in p1.X:
    htab_p1[HashToCurve(y)] = y
peer_pl = []
for h in unmapped:
    if h in htab_p1:
        peer_pl.append(htab_p1[h])
print(f'Step 7: P0 -> P1: unmapped H values ({len(unmapped)})')
print(f'  P1 maps these to Y+ ({len(Y_plus)}) and Y ({len(p1.X)})')
print(f'  Resolved: {len(peer_pl)} elements')

Ui_new = sorted(Ui_new_p0 + peer_pl)
print(f'Step 8: P0 -> P1: final U1 = {len(Ui_new)} plaintext elements')
print()

# ─── Verify ───
print('─' * 40)
print('VERIFICATION')
print('─' * 40)

X_cur = set(X); Y_cur = set(Y)
for x in X_minus: X_cur.discard(x)
for y in Y_minus: Y_cur.discard(y)
for x in X_plus: X_cur.add(x)
for y in Y_plus: Y_cur.add(y)
U_gt = sorted(X_cur | Y_cur)

print(f'Protocol output: |U1| = {len(Ui_new)}')
print(f'Ground truth:   |U1| = {len(U_gt)}')
ok = sorted(Ui_new) == U_gt
print(f'CORRECT: {ok}')
print()

# Show what's in the final union
print('Final U1 element sources:')
from_Y_orig = set(Ui_new) & (ys - xs - set(Y_minus))
from_X_orig = set(Ui_new) & (xs - ys - set(X_minus))
from_inter = set(Ui_new) & (xs & ys - set(X_minus) - set(Y_minus))
from_Xplus = set(Ui_new) & set(X_plus)
from_Yplus = set(Ui_new) & set(Y_plus)
print(f'  From original X\\Y (surviving):  {len(from_X_orig)}')
print(f'  From original Y\\X (surviving):  {len(from_Y_orig)}')
print(f'  From original X cap Y (surviving): {len(from_inter)}')
print(f'  From X+ (P0 additions):          {len(from_Xplus)}')
print(f'  From Y+ (P1 additions):          {len(from_Yplus)}')
print(f'  Total: {len(from_X_orig) + len(from_Y_orig) + len(from_inter) + len(from_Xplus) + len(from_Yplus)}')
