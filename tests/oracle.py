"""
oracle.py -- an INDEPENDENT cleartext reference implementation of the Derive
function specified in ao-prf_wProofs.tex (sections 1-4, 7, 8).

PURPOSE. bip32-hydra.mpc produces stable output, which is weak evidence: a
wrong-but-deterministic function does too. This file computes the same
function a second time, from the written specification, so the two can be
differentially tested.

LANGUAGE CHOICE: plain Python, not SageMath. Everything the specification
needs is modular integer arithmetic on values < 2^129 plus SHAKE128. Python's
ints are arbitrary precision and hashlib ships shake_128, so Sage buys nothing
here; avoiding it keeps the oracle runnable anywhere with no CAS install. Sage
would only be required for the MATRIX SEARCH (minimal-polynomial irreducibility
tests), and that is deliberately out of scope: the matrices are PARAMETERS,
given in tex sec.1.2, not logic this oracle should re-derive.

INDEPENDENCE. The PRF structure, the encodings, the serialization and the
secp256k1 reduction are implemented from the tex's prose/equations. Nothing is
imported, ported or copied from bip32-hydra.mpc. Two exceptions are documented
honestly, both forced by gaps in the tex, and both marked SPEC-GAP below:
  (1) the SHAKE128 round-constant derivation, which the tex never specifies;
  (2) the round-constant INDEXING across the three body loops.
Both were taken from the Hydra authors' own hydra.sage (external to this
project's work), not from bip32-hydra.mpc. The anchor test in
test_anchor_authors.py verifies (1) and (2) byte-exactly against hydra.sage's
published output at the authors' own parameters.
"""

from hashlib import shake_128
from math import ceil, gcd


# ────────────────────────────────────────────────────────────────────────
# Frozen parameters -- tex sec.1 (single source of truth; see constants.json)
# ────────────────────────────────────────────────────────────────────────

P_THESIS = 2**128 + 385                      # tex sec.1.1
KAPPA = 128
R_E1, R_E2 = 2, 4                            # tex sec.1, "2 initial + 4 final"
R_I_THESIS = 42                              # tex sec.1
R_H_THESIS = 39                              # tex sec.1

# tex sec.1.2, given in plain form (the actual matrix entries).
M_E = [[3, 2, 1, 1],
       [1, 3, 2, 1],
       [1, 1, 3, 2],
       [2, 1, 1, 3]]

M_I_THESIS = [[2, 1, 1, 1],
              [2, 2, 1, 1],
              [2, 1, 3, 1],
              [3, 1, 1, 8]]

M_J_THESIS = [[5, 1, 1, 1, 1, 1, 1, 1],
              [6, 2, 1, 1, 1, 1, 1, 1],
              [4, 1, 6, 1, 1, 1, 1, 1],
              [9, 1, 1, 9, 1, 1, 1, 1],
              [3, 1, 1, 1, 4, 1, 1, 1],
              [8, 1, 1, 1, 1, 7, 1, 1],
              [7, 1, 1, 1, 1, 1, 8, 1],
              [2, 1, 1, 1, 1, 1, 1, 5]]

# tex sec.8: order of secp256k1.
N_SECP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# tex sec.4.3: delta_0 is the little-endian F_p-encoding of the 14-byte ASCII
# string "BIP32-HYDRA-hd"; delta_1 = delta_2 = 0. Computed here from the
# string, exactly as the tex says a verifier should ("a verifier reproduces
# the choice from the string"), rather than copied as a magic number.
DOMAIN_TAG_STRING = b"BIP32-HYDRA-hd"
DELTA_0 = int.from_bytes(DOMAIN_TAG_STRING, "little")
DELTA_1 = 0
DELTA_2 = 0


# ────────────────────────────────────────────────────────────────────────
# SPEC-GAP (1): round-constant derivation.
# The tex fixes p, d, the round counts, the three matrices, the deltas and n,
# but NEVER specifies the per-round constants c. Without them E_K is not
# computable from the tex alone. Procedure below follows the Hydra paper's
# Appendix ("pseudo-randomly generate all matrices and constants using
# Shake-128 seeded with the string Hydra and the used prime") at the byte
# level, matching hydra.sage.
# ────────────────────────────────────────────────────────────────────────

class ShakeStream:
    """Streaming XOF reader. SHAKE is an extendable-output function, so the
    first n bytes of digest(m) are stable for every m >= n; we exploit that to
    emulate Cryptodome's incremental shake.read(n) using hashlib."""

    def __init__(self, seed: bytes):
        self._seed = seed
        self._pos = 0
        self._buf = b""

    def read(self, n: int) -> bytes:
        need = self._pos + n
        if len(self._buf) < need:
            grow = max(need, 2 * len(self._buf), 1024)
            self._buf = shake_128(self._seed).digest(grow)
        out = self._buf[self._pos:self._pos + n]
        self._pos += n
        return out


def init_shake(p: int, label: str) -> ShakeStream:
    """Seed = "Hydra" || label || the prime as little-endian 64-bit blocks."""
    bitlen = p.bit_length()
    num = ceil(bitlen / 64)
    seed = b"Hydra" + label.encode("ascii")
    for i in range(num):
        block = (p >> (i * 64)) & ((1 << 64) - 1)
        seed += int(block).to_bytes(8, "little")
    return ShakeStream(seed)


def field_element_from_shake(stream: ShakeStream, p: int) -> int:
    """Rejection-sample one element of F_p. Reads ceil(bitlen/8) bytes, packs
    them into ceil(bytes/8) little-endian 64-bit words, reassembles
    most-significant-word-first, and rejects anything >= p."""
    bitlen = p.bit_length()
    nbytes = ceil(bitlen / 8)
    nwords = ceil(nbytes / 8)
    while True:
        buf = stream.read(nbytes)
        words = []
        for i in range(nwords):
            chunk = bytearray(8)
            for j in range(i * 8, min((i + 1) * 8, nbytes)):
                chunk[j - i * 8] = buf[j]
            words.append(int.from_bytes(bytes(chunk), "little"))
        res = 0
        for w in reversed(words):
            res = (res << 64) + w
        if res < p:
            return res


def gen_round_constants(stream: ShakeStream, rounds: int, width: int, p: int):
    return [[field_element_from_shake(stream, p) for _ in range(width)]
            for _ in range(rounds)]


# ────────────────────────────────────────────────────────────────────────
# The Hydra PRF -- tex sec.3
# ────────────────────────────────────────────────────────────────────────

def smallest_valid_d(p: int) -> int:
    """tex sec.1: d is the smallest odd integer with gcd(d, p-1) = 1."""
    d = 3
    while gcd(d, p - 1) != 1:
        d += 2
    return d


def matvec(M, v, p):
    return [sum(M[r][c] * v[c] for c in range(len(v))) % p for r in range(len(M))]


def vadd(a, b, p):
    return [(x + y) % p for x, y in zip(a, b)]


class HydraOracle:
    def __init__(self, p, M_I, M_J, R_I, R_H, M_Ext=None):
        self.p = p
        self.d = smallest_valid_d(p)
        self.M_E = M_Ext if M_Ext is not None else M_E
        self.M_I = M_I
        self.M_J = M_J
        self.R_I = R_I
        self.R_H = R_H

        # NOTE: "Constants" is seeded on a FRESH stream, independent of the
        # "Matrices" stream. So the round constants do not depend on how much
        # output the matrix search consumed -- which is why this oracle can
        # reproduce them without implementing that search at all.
        s = init_shake(p, "Constants")
        self.rc_B = gen_round_constants(s, R_E1 + R_E2 + R_I, 4, p)
        self.rc_H = gen_round_constants(s, R_H, 8, p)

    # --- nonlinear layers, tex sec.2 -----------------------------------

    def S_E(self, state):
        """Def. S_E: componentwise power map x -> x^d."""
        return [pow(x, self.d, self.p) for x in state]

    def S_I(self, state):
        """Def. S_I: y_l = x_l + ( (sum (-1)^j x_j)^2 + (sum (-1)^floor(j/2) x_j) )^2."""
        p = self.p
        dot1 = (state[0] - state[1] + state[2] - state[3]) % p
        dot2 = (state[0] + state[1] - state[2] - state[3]) % p
        inner = (dot1 * dot1 + dot2) % p
        prod = (inner * inner) % p
        return [(x + prod) % p for x in state]

    def S_J(self, state):
        """Def. S_J: y_l = x_l + (sum (-1)^floor(h/4) x_h)^2."""
        p = self.p
        dot = (state[0] + state[1] + state[2] + state[3]
               - state[4] - state[5] - state[6] - state[7]) % p
        sq = (dot * dot) % p
        return [(x + sq) % p for x in state]

    # --- body, tex sec.3.1 ---------------------------------------------

    def body(self, state):
        """2 initial external rounds, R_I internal rounds, 4 final external
        rounds. Megafono sum accumulates every intermediate state EXCEPT the
        last (tex sec.3.1: z = sum_{r=1}^{R-1} s^(r), y = s^(R)).

        SPEC-GAP (2): the tex says only "the public round constant" and never
        fixes which constant belongs to which round. Consumed here in
        sequential order across the three loops, which is the only assignment
        consistent with drawing them from one stream in order.
        """
        p = self.p
        z = [0, 0, 0, 0]
        state = matvec(self.M_E, state, p)          # initial linear layer
        for i in range(R_E1):
            state = self.S_E(state)
            state = vadd(matvec(self.M_E, state, p), self.rc_B[i], p)
            z = vadd(z, state, p)
        for i in range(self.R_I):
            state = self.S_I(state)
            state = vadd(matvec(self.M_I, state, p), self.rc_B[i + R_E1], p)
            z = vadd(z, state, p)
        for i in range(R_E1, R_E1 + R_E2):
            state = self.S_E(state)
            state = vadd(matvec(self.M_E, state, p), self.rc_B[i + self.R_I], p)
            if i < R_E1 + R_E2 - 1:
                z = vadd(z, state, p)
        return state, z

    # --- heads, tex sec.3.3 --------------------------------------------

    def head(self, v, K_prime):
        """R_H rounds of J(v) = M_J . S_J(v) + c, with K' injected after each."""
        p = self.p
        for r in range(self.R_H):
            v = self.S_J(v)
            v = vadd(matvec(self.M_J, v, p), self.rc_H[r], p)
            v = vadd(v, K_prime, p)
        return v

    # --- the PRF, tex sec.3.4 ------------------------------------------

    def E_K(self, K, m, t=4):
        """E_K(m). Steps exactly as tex sec.3.4 numbers them."""
        p = self.p
        assert len(K) == 4 and len(m) == 4
        if t > 8:
            raise NotImplementedError(
                "t > 8 needs the rolling function R (tex cites Hydra's "
                "extendable output); out of scope -- this construction uses "
                "a single 4-word block.")

        # 1. Pre-whitening.
        s = vadd(m, K, p)
        # 2. Body, then y <- y_raw + K.
        y_raw, z = self.body(s)
        y = vadd(y_raw, K, p)
        # Key expansion, tex sec.3.2.
        K_prime = list(K) + matvec(self.M_E, list(K), p)
        # 3. Head input.
        v = list(y) + list(z)
        # 4. Head with feed-forward.
        out = vadd(self.head(v, K_prime), v, p)
        # 5. Truncation.
        return out[:t]


# ────────────────────────────────────────────────────────────────────────
# Derivation wrapper -- tex sec.4.3, sec.7, sec.8
# ────────────────────────────────────────────────────────────────────────

MASK128 = (1 << 128) - 1


def KeyEnc(k_par: int, c_par: int):
    """tex sec.4.3: split each 256-bit secret into two 128-bit words,
    K = (k_hi, k_lo, c_hi, c_lo)."""
    assert 0 <= k_par < 2**256 and 0 <= c_par < 2**256
    return [k_par >> 128, k_par & MASK128, c_par >> 128, c_par & MASK128]


def InEnc(index: int):
    """tex sec.4.3: m = (e, delta_0, delta_1, delta_2), where e packs
    0x00 || ser32(index). Prepending a zero byte to a big-endian number does
    not change its integer value, so e == index."""
    assert 2**31 <= index < 2**32, "hardened index required"
    return [index, DELTA_0, DELTA_1, DELTA_2]


def serialize(words, p):
    """tex sec.7. Returns (accepted, I_bytes). Rejects if any word >= 2^128.

    SPEC-AMBIGUITY (3), RESOLVED 2026-11-14 (thesisToPaper/261114.tex): each
    word is a 16-byte BIG-endian string, words 0..3 in order, so BIP32's
    parse256(I[:32]) == c0*2^128 + c1 == the limb scalar of sec.8 (and the
    same for I_R). Before 2026-11-14 this was little-endian per word, which
    did not match the limbs; only this informational octet string changed,
    the child-key arithmetic always used the limbs.
    """
    if any(w >= 2**128 for w in words):
        return False, None
    blob = b"".join(w.to_bytes(16, "big") for w in words)
    return True, blob


def parse256(b):
    """BIP32's parse256: a 32-byte string read as a big-endian integer."""
    assert len(b) == 32
    return int.from_bytes(b, "big")


def scalars_from_words(words):
    """tex sec.8: I_L = (c0, c1), I_R = (c2, c3), each x = x_hi*2^128 + x_lo."""
    I_L = (words[0] << 128) | words[1]
    I_R = (words[2] << 128) | words[3]
    return I_L, I_R


def child_scalar(I_L: int, k_par: int):
    """tex sec.8.2, BIP32's additive rule (restored 2026-11-02, replacing the
    short-lived "option (b)" k_child = I_L):

        k_child = (I_L + k_par) mod n,   c_child = I_R

    Rejected (BIP32: "proceed with the next value for i") if I_L >= n or
    k_child == 0. Returns (ok, k_child)."""
    if I_L >= N_SECP:
        return False, None
    k_child = (I_L + k_par) % N_SECP
    if k_child == 0:
        return False, None
    return True, k_child


def derive(oracle: HydraOracle, k_par: int, c_par: int, index: int,
           max_retries: int = 64, force_ovf: int = 0, force_bad: int = 0):
    """Full Derive per Algorithm 1 (tex sec.4.3): retry with an incremented
    public counter on either rejection branch. Returns a dict describing the
    whole attempt chain, so the harness can assert on the retry path too.

    k_par enters twice, as in BIP32: through KeyEnc (the PRF key) and as the
    additive offset in the child-scalar step.

    force_ovf / force_bad: TEST HOOK mirroring poc_derive.mpc. Attempt number
    a (0-based) is treated as an overflow rejection if a < force_ovf, and --
    only if its real overflow check passed -- as an I_L rejection if
    force_ovf <= a < force_ovf + force_bad. Both real rejection branches are
    ~2^-116 / ~2^-128 events, so this is the only way to make the retry path
    actually run; it alters nothing else.
    """
    ctr = index
    attempts = []
    for a in range(max_retries):
        K = KeyEnc(k_par, c_par)
        m = InEnc(ctr)
        words = oracle.E_K(K, m, t=4)
        ok_ser, blob = serialize(words, oracle.p)
        if not ok_ser or a < force_ovf:
            attempts.append({"ctr": ctr, "words": words,
                             "reject": "overflow" if not ok_ser
                             else "overflow(forced)"})
            ctr += 1
            continue
        I_L, I_R = scalars_from_words(words)
        ok_child, k_child = child_scalar(I_L, k_par)
        forced_bad = force_ovf <= a < force_ovf + force_bad
        if not ok_child or forced_bad:
            reason = ("I_L>=n" if I_L >= N_SECP else "k_child==0") \
                if not ok_child else "bad(forced)"
            attempts.append({"ctr": ctr, "reject": reason, "words": words})
            ctr += 1
            continue
        attempts.append({"ctr": ctr, "reject": None, "words": words})
        return {
            "ok": True, "ctr_final": ctr, "skips": len(attempts) - 1,
            "words": words, "I_hex": blob.hex(),
            "I_L": I_L, "I_R": I_R,
            "k_child": k_child, "c_child": I_R,
            "attempts": attempts,
        }
    raise RuntimeError("exceeded max_retries")


def thesis_oracle():
    return HydraOracle(P_THESIS, M_I_THESIS, M_J_THESIS, R_I_THESIS, R_H_THESIS)


if __name__ == "__main__":
    o = thesis_oracle()
    print(f"p = {o.p}")
    print(f"d = {o.d}  (expect 3)")
    print(f"R_E1={R_E1} R_E2={R_E2} R_I={o.R_I} R_H={o.R_H}")
    print(f"DELTA_0 = {DELTA_0}")
    print(f"rc_B[0] = {o.rc_B[0]}")
    print(f"rc_H[0] = {o.rc_H[0]}")
    # The exact input bip32-hydra.mpc's main() hardcodes: K=0, m=(N,IV)=(2,1,1,1)
    print("\nE_K(K=[0,0,0,0], m=[2,1,1,1]):")
    for i, w in enumerate(o.E_K([0, 0, 0, 0], [2, 1, 1, 1], t=4)):
        print(f"  word {i} = {w}")
