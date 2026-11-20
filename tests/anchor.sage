"""
anchor.sage -- external anchor for oracle.py.

Loads the Hydra authors' OWN reference implementation (hydra.sage) completely
unmodified, at THEIR parameters (p = 2^127+45, t = 5, kappa = 128), and dumps:
  - the matrices M_I / M_J that their SHAKE-driven search produces,
  - their first body and head round constants,
  - the keystream gen_ks(t=5, K=0, IV=(1,1,1), N=2).

oracle.py is then fed the same matrices (matrices are PARAMETERS) and must
reproduce the keystream exactly. That check validates the oracle's PRF logic
AND its SHAKE128 round-constant derivation byte-for-byte against the authors'
code, at parameters that have nothing to do with this thesis -- so it cannot be
an accidental agreement produced by shared thesis-specific constants.
"""

load("hydra.sage")

# hydra, F, p, t are defined by hydra.sage's own driver.
print("ANCHOR_PRIME", int(p))
print("ANCHOR_D", int(hydra.d))
print("ANCHOR_RE1", int(hydra.Re_1))
print("ANCHOR_RE2", int(hydra.Re_2))
print("ANCHOR_RI", int(hydra.Ri))
print("ANCHOR_RH", int(hydra.Rh))

print("ANCHOR_MI", [[int(hydra.Mi[i, j]) for j in range(4)] for i in range(4)])
print("ANCHOR_MJ", [[int(hydra.Mh[i, j]) for j in range(8)] for i in range(8)])
print("ANCHOR_ME", [[int(hydra.Me[i, j]) for j in range(4)] for i in range(4)])

print("ANCHOR_RCB0", [int(x) for x in hydra.rc_b[0]])
print("ANCHOR_RCH0", [int(x) for x in hydra.rc_h[0]])
print("ANCHOR_NUM_RCB", int(len(hydra.rc_b)))
print("ANCHOR_NUM_RCH", int(len(hydra.rc_h)))

MK = [F(0), F(0), F(0), F(0)]
IV = [F(1), F(1), F(1)]
N = F(2)
ks = hydra.gen_ks(5, MK, IV, N)
print("ANCHOR_KEYSTREAM", [int(x) for x in ks])

# A second, non-trivial key/input so the anchor is not only the all-zero case.
MK2 = [F(0x1234567890ABCDEF), F(0xFEDCBA0987654321), F(7), F(2**100 + 3)]
IV2 = [F(11), F(22), F(33)]
N2 = F(2**31)
ks2 = hydra.gen_ks(5, MK2, IV2, N2)
print("ANCHOR_KEYSTREAM2", [int(x) for x in ks2])
