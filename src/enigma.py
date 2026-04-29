import random

# All printable ASCII characters (space through ~) — 96 characters, even number required for reflector pairing
CHARSET = ''.join(chr(i) for i in range(32, 128))
N = len(CHARSET)  # 96 — replaces all hardcoded 26s throughout the code


def _generate_rotor_wiring(seed):
    """Generate a deterministic rotor wiring permutation from a seed.
    We can no longer use historical Enigma wirings since those are A-Z only."""
    indices = list(range(N))
    random.seed(seed)
    random.shuffle(indices)
    return indices


def _generate_reflector_wiring(seed):
    """Generate a deterministic symmetric reflector wiring.
    Must be symmetric — if A maps to B then B maps to A.
    N must be even so every character has exactly one pair."""
    indices = list(range(N))
    random.seed(seed)
    random.shuffle(indices)
    wiring = [0] * N
    # Walk through in pairs and swap them symmetrically
    for i in range(0, N, 2):
        a, b = indices[i], indices[i + 1]
        wiring[a] = b
        wiring[b] = a
    return wiring


class Rotor:
    def __init__(self, wiring: list, notch: str, position: int = 0, ring_setting: int = 0):
        # Wiring is now a pre-generated list of ints, no string conversion needed
        self.wiring = wiring

        # Pre-compute inverse wiring for the backward pass
        self.wiring_inverse = [0] * N
        for i, v in enumerate(self.wiring):
            self.wiring_inverse[v] = i

        # Convert notch character to CHARSET index instead of ord() - ord('A')
        self.notch = CHARSET.index(notch)

        self.position = position
        self.ring_setting = ring_setting

    def step(self):
        # Wrap around N instead of 26
        self.position = (self.position + 1) % N

    def is_at_notch(self):
        return self.position == self.notch

    def forward(self, signal):
        effective_input  = (signal + self.position) % N
        raw_output       = self.wiring[effective_input]
        effective_output = (raw_output - self.position + N) % N  # + N instead of + 26
        return effective_output

    def backward(self, signal):
        effective_input  = (signal + self.position) % N
        raw_output       = self.wiring_inverse[effective_input]
        effective_output = (raw_output - self.position + N) % N
        return effective_output


class Plugboard:
    def __init__(self, pairs):
        # Neutral mapping — every character maps to itself
        self.mapping = list(range(N))

        # Apply swaps using CHARSET index instead of ord() - ord('A')
        for a, b in pairs:
            a = CHARSET.index(a)
            b = CHARSET.index(b)
            self.mapping[a] = b
            self.mapping[b] = a

    def swap(self, signal):
        return self.mapping[signal]


class Reflector:
    def __init__(self, wiring: list):
        # Wiring is now a pre-generated list of ints
        self.wiring = wiring

    def reflect(self, signal):
        return self.wiring[signal]


class EnigmaMachine:
    def __init__(self, rotors, reflector, plugboard):
        self.rotors    = rotors
        self.reflector = reflector
        self.plugboard = plugboard

    def step_rotors(self):
        # Double-step: middle rotor at notch — step both left and middle
        if self.rotors[1].is_at_notch():
            self.rotors[0].step()
            self.rotors[1].step()
        # Normal carry: right rotor at notch — step middle
        elif self.rotors[2].is_at_notch():
            self.rotors[1].step()

        # Right rotor always steps on every keypress
        self.rotors[2].step()

    def press_key(self, char):
        # Pass through unsupported characters unchanged
        if char not in CHARSET:
            return char

        self.step_rotors()

        # Convert character to CHARSET index instead of ord() - ord('A')
        signal = CHARSET.index(char)

        # Signal path: plugboard → rotors forward → reflector → rotors backward → plugboard
        signal = self.plugboard.swap(signal)
        signal = self.rotors[2].forward(signal)
        signal = self.rotors[1].forward(signal)
        signal = self.rotors[0].forward(signal)
        signal = self.reflector.reflect(signal)
        signal = self.rotors[0].backward(signal)
        signal = self.rotors[1].backward(signal)
        signal = self.rotors[2].backward(signal)
        signal = self.plugboard.swap(signal)

        # Convert index back to character using CHARSET instead of chr() + ord('A')
        return CHARSET[signal]


def main():
    # Generate wirings from fixed seeds — same seed always produces the same wiring
    ROTOR_I_WIRING   = _generate_rotor_wiring(seed=42)
    ROTOR_II_WIRING  = _generate_rotor_wiring(seed=99)
    ROTOR_III_WIRING = _generate_rotor_wiring(seed=7)
    REFLECTOR_WIRING = _generate_reflector_wiring(seed=21)

    # Notch characters — can now be any character in CHARSET
    ROTOR_I_NOTCH   = 'Y'
    ROTOR_II_NOTCH  = 'M'
    ROTOR_III_NOTCH = 'v'

    # Plugboard pairs — can now swap any characters including symbols, digits, spaces
    PAIRS = [('A', 'z'), ('B', 'y'), ('1', '9'), (' ', '!')]

    def build_machine():
        """Helper to build a fresh machine with identical settings."""
        return EnigmaMachine(
            rotors=[
                Rotor(ROTOR_I_WIRING,   ROTOR_I_NOTCH,   position=0),
                Rotor(ROTOR_II_WIRING,  ROTOR_II_NOTCH,  position=0),
                Rotor(ROTOR_III_WIRING, ROTOR_III_NOTCH, position=0)
            ],
            reflector=Reflector(REFLECTOR_WIRING),
            plugboard=Plugboard(PAIRS)
        )

    # Encrypt
    message   = input("Enter message: ")
    encrypted = "".join(build_machine().press_key(c) for c in message)
    print(f"Encrypted: {encrypted}")

    # Decrypt — must reset to identical starting state
    decrypted = "".join(build_machine().press_key(c) for c in encrypted)
    print(f"Decrypted: {decrypted}")


if __name__ == "__main__":
    main()