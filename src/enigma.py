import hashlib
import secrets

CHARSET = ''.join(chr(i) for i in range(32, 128))
N = len(CHARSET)  # 96 characters


# ─────────────────────────────────────────────
# HARDENED WIRING GENERATION
# Replaces random.shuffle() with SHA-256 driven
# Fisher-Yates — cryptographically unpredictable
# without knowing the seed
# ─────────────────────────────────────────────

def _deterministic_shuffle(seed: int) -> list:
    """
    Fisher-Yates shuffle driven by SHA-256 hash chain.
    random.shuffle() uses Python's Mersenne Twister which is
    NOT cryptographically secure — its state can be recovered
    after observing enough output. SHA-256 cannot be reversed.
    """
    indices = list(range(N))
    key = hashlib.sha256(str(seed).encode()).digest()
    for i in range(N - 1, 0, -1):
        # Each swap index derived from a unique hash — cannot be predicted
        hash_val = int(hashlib.sha256(key + i.to_bytes(4, 'big')).hexdigest(), 16)
        j = hash_val % (i + 1)
        indices[i], indices[j] = indices[j], indices[i]
    return indices


def _generate_rotor_wiring(seed: int) -> list:
    return _deterministic_shuffle(seed)


def _generate_non_involutory_reflector(seed: int) -> list:
    """
    FIX 1 — Self-reciprocal cipher:
        Old reflector was symmetric: if A->Z then Z->A
        This made encrypt() == decrypt() which is a known structural weakness.
        A non-involutory reflector breaks that symmetry — encrypt and decrypt
        now follow completely different signal paths.

    FIX 2 — Letter can never encrypt to itself:
        The old symmetric reflector guaranteed no fixed points.
        A non-involutory permutation has no such constraint —
        a character CAN map to itself, removing a known crib attack vector.
    """
    return _deterministic_shuffle(seed)


def _generate_keystream(master_key: bytes, length: int) -> list:
    """
    FIX 3 — Statistical attacks:
        Without this, letter frequencies survive through the rotor
        substitutions. English 'E' still appears most often in ciphertext.
        This keystream adds a unique position-dependent offset to every
        output character, flattening the frequency distribution completely.
        Each position gets a different shift — identical plaintexts at
        different positions produce different ciphertext.
    """
    stream = []
    for i in range(length):
        val = int(hashlib.sha256(master_key + i.to_bytes(8, 'big')).hexdigest(), 16) % N
        stream.append(val)
    return stream


# ─────────────────────────────────────────────
# ROTOR — unchanged internally, N replaces 26
# ─────────────────────────────────────────────

class Rotor:
    def __init__(self, wiring: list, notch: str, position: int = 0, ring_setting: int = 0):
        self.wiring = wiring

        self.wiring_inverse = [0] * N
        for i, v in enumerate(self.wiring):
            self.wiring_inverse[v] = i

        self.notch       = CHARSET.index(notch)
        self.position    = position
        self.ring_setting = ring_setting

    def step(self):
        self.position = (self.position + 1) % N

    def is_at_notch(self):
        return self.position == self.notch

    def forward(self, signal):
        effective_input  = (signal + self.position) % N
        raw_output       = self.wiring[effective_input]
        effective_output = (raw_output - self.position + N) % N
        return effective_output

    def backward(self, signal):
        effective_input  = (signal + self.position) % N
        raw_output       = self.wiring_inverse[effective_input]
        effective_output = (raw_output - self.position + N) % N
        return effective_output


# ─────────────────────────────────────────────
# PLUGBOARD — unchanged
# ─────────────────────────────────────────────

class Plugboard:
    def __init__(self, pairs):
        self.mapping = list(range(N))
        for a, b in pairs:
            a = CHARSET.index(a)
            b = CHARSET.index(b)
            self.mapping[a] = b
            self.mapping[b] = a

    def swap(self, signal):
        return self.mapping[signal]


# ─────────────────────────────────────────────
# REFLECTOR — now non-involutory
# Stores both wiring AND its inverse so the
# machine can take a separate decryption path
# ─────────────────────────────────────────────

class Reflector:
    def __init__(self, wiring: list):
        self.wiring = wiring

        # Pre-compute inverse — needed because wiring is no longer symmetric
        self.wiring_inverse = [0] * N
        for i, v in enumerate(self.wiring):
            self.wiring_inverse[v] = i

    def reflect(self, signal):
        """Encryption path"""
        return self.wiring[signal]

    def reflect_inverse(self, signal):
        """Decryption path — different result from reflect()"""
        return self.wiring_inverse[signal]


# ─────────────────────────────────────────────
# ENIGMA MACHINE
# Now has separate press_key() and decrypt_key()
# because the cipher is no longer self-reciprocal
# ─────────────────────────────────────────────

class EnigmaMachine:
    def __init__(self, rotors, reflector, plugboard, master_key: bytes):
        self.rotors      = rotors
        self.reflector   = reflector
        self.plugboard   = plugboard
        self.master_key  = master_key
        self._ks_pos     = 0  # keystream position counter

    def _next_ks(self, keystream: list) -> int:
        """Consume the next keystream value and advance the counter"""
        val = keystream[self._ks_pos]
        self._ks_pos += 1
        return val

    def step_rotors(self):
        if self.rotors[1].is_at_notch():
            self.rotors[0].step()
            self.rotors[1].step()
        elif self.rotors[2].is_at_notch():
            self.rotors[1].step()
        self.rotors[2].step()

    def press_key(self, char: str, keystream: list) -> str:
        """
        Encrypt one character.
        Signal path: plug → R3→R2→R1 forward → reflect → R1→R2→R3 backward → plug → keystream
        """
        if char not in CHARSET:
            return char

        self.step_rotors()
        signal = CHARSET.index(char)

        signal = self.plugboard.swap(signal)
        signal = self.rotors[2].forward(signal)
        signal = self.rotors[1].forward(signal)
        signal = self.rotors[0].forward(signal)
        signal = self.reflector.reflect(signal)       # non-involutory forward
        signal = self.rotors[0].backward(signal)
        signal = self.rotors[1].backward(signal)
        signal = self.rotors[2].backward(signal)
        signal = self.plugboard.swap(signal)

        # Apply keystream — unique shift per position destroys frequency patterns
        signal = (signal + self._next_ks(keystream)) % N
        return CHARSET[signal]

    def decrypt_key(self, char: str, keystream: list) -> str:
        """
        Decrypt one character.
        Signal path is NOT the same as encrypt — reflect_inverse() is used instead.
        This only works because we broke the self-reciprocal property intentionally.
        """
        if char not in CHARSET:
            return char

        self.step_rotors()
        signal = CHARSET.index(char)

        # Undo keystream first before entering rotors
        signal = (signal - self._next_ks(keystream) + N) % N

        signal = self.plugboard.swap(signal)
        signal = self.rotors[2].forward(signal)
        signal = self.rotors[1].forward(signal)
        signal = self.rotors[0].forward(signal)
        signal = self.reflector.reflect_inverse(signal)  # non-involutory inverse
        signal = self.rotors[0].backward(signal)
        signal = self.rotors[1].backward(signal)
        signal = self.rotors[2].backward(signal)
        signal = self.plugboard.swap(signal)

        return CHARSET[signal]


def main():
    ROTOR_I_WIRING   = _generate_rotor_wiring(seed=42)
    ROTOR_II_WIRING  = _generate_rotor_wiring(seed=99)
    ROTOR_III_WIRING = _generate_rotor_wiring(seed=7)
    REFLECTOR_WIRING = _generate_non_involutory_reflector(seed=21)

    ROTOR_I_NOTCH    = 'Y'
    ROTOR_II_NOTCH   = 'M'
    ROTOR_III_NOTCH  = 'v'

    PAIRS = [('A', 'z'), ('B', 'y'), ('1', '9'), (' ', '!')]

    # secrets.token_bytes() generates cryptographically secure random bytes
    # In a real system this key would be securely shared between sender and receiver
    MASTER_KEY = secrets.token_bytes(32)

    def build_machine():
        """Always returns a fresh machine at identical starting state"""
        return EnigmaMachine(
            rotors=[
                Rotor(ROTOR_I_WIRING,   ROTOR_I_NOTCH,   position=0),
                Rotor(ROTOR_II_WIRING,  ROTOR_II_NOTCH,  position=0),
                Rotor(ROTOR_III_WIRING, ROTOR_III_NOTCH, position=0)
            ],
            reflector=Reflector(REFLECTOR_WIRING),
            plugboard=Plugboard(PAIRS),
            master_key=MASTER_KEY
        )

    message   = input("Enter message: ")
    keystream = _generate_keystream(MASTER_KEY, len(message))
    encrypted = "".join(build_machine().press_key(c, keystream) for c in message)
    print(f"Encrypted: {encrypted}")

    keystream = _generate_keystream(MASTER_KEY, len(encrypted))
    decrypted = "".join(build_machine().decrypt_key(c, keystream) for c in encrypted)
    print(f"Decrypted: {decrypted}")


if __name__ == "__main__":
    main()