class Rotor:
    def __init__(self, wiring: str, notch: str, position: int = 0, ring_setting: int = 0):
        # Convert Wiring Str to List of Ints once, each position in list is relative to position of capital A
        self.wiring = [ord(c) - ord('A') for c in wiring]

        self.wiring_inverse = [0] * 26
        for i,v in enumerate(self.wiring):
            self.wiring_inverse[v] = i

        # Converts Notch Letter to Int for easy comparison
        self.notch = ord(notch) - ord('A')

        self.position = position
        self.ring_setting = ring_setting

    def step(self):
        self.position = (self.position + 1) % 26

    def is_at_notch(self):
        return self.position == self.notch

    def forward(self, signal):
        effective_input = (signal + self.position) % 26
        raw_output = self.wiring[effective_input]
        effective_output = (raw_output - self.position + 26) % 26
        return effective_output

    def backward(self, signal):
        effective_input = (signal + self.position) % 26
        raw_output = self.wiring_inverse[effective_input]
        effective_output = (raw_output - self.position + 26) % 26
        return effective_output

class Plugboard:
    def __init__(self,pairs):
        self.mapping = list(range(26))

        for a,b in pairs:
            a = ord(a) - ord('A')
            b = ord(b) - ord('A')
            self.mapping[a] = b
            self.mapping[b] = a
    
    def swap(self, signal):
        return self.mapping[signal]

class Reflector:
    def __init__(self, wiring):
        # Convert Wiring Str to List of ints
        self.wiring = [ord(c) - ord('A') for c in wiring] 

    def reflect(self, signal):
        return self.wiring[signal]

class EnigmaMachine:
    def __init__(self, rotors, reflector, plugboard):
        self.rotors = rotors
        self.reflector = reflector
        self.plugboard = plugboard

    def step_rotors(self):
        if self.rotors[1].is_at_notch():
            self.rotors[0].step()
            self.rotors[1].step()
        elif self.rotors[2].is_at_notch():
            self.rotors[1].step()
        
        self.rotors[2].step()

    def press_key(self, letter):
        self.step_rotors()
        signal = ord(letter) - ord('A')
        signal = self.plugboard.swap(signal)
        signal = self.rotors[2].forward(signal)
        signal = self.rotors[1].forward(signal)
        signal = self.rotors[0].forward(signal)
        signal = self.reflector.reflect(signal)
        signal = self.rotors[0].backward(signal)
        signal = self.rotors[1].backward(signal)
        signal = self.rotors[2].backward(signal)
        signal = self.plugboard.swap(signal)
        return chr(signal + ord('A'))
    
def main():
    # Constants
    ROTOR_I     = ("EKMFLGDQVZNTOWYHXUSPAIBRCJ", "Y")
    ROTOR_II    = ("AJDKSIRUXBLHWTMCQGZNPYFVOE", "M")
    ROTOR_III   = ("BDFHJLCPRTXVZNYEIWGAKMUSQO", "V")
    REFLECTOR_B = "YRUHQSLDPXNGOKMIEBFZCWVJAT"

    # Setup machine
    machine = EnigmaMachine(
        rotors=[
            Rotor(ROTOR_I[0],   ROTOR_I[1],   position=0),
            Rotor(ROTOR_II[0],  ROTOR_II[1],  position=0),
            Rotor(ROTOR_III[0], ROTOR_III[1], position=0)
        ],
        reflector=Reflector(REFLECTOR_B),
        plugboard=Plugboard([('A', 'Z'), ('B', 'Y'), ('C', 'X')])
    )

    # Encrypt
    message = input("Enter Message: ").upper().replace(" ", "")
    encrypted = "".join(machine.press_key(c) for c in message)
    print(f"Encrypted: {encrypted}")

    # Reset and decrypt
    machine = EnigmaMachine(
        rotors=[
            Rotor(ROTOR_I[0],   ROTOR_I[1],   position=0),
            Rotor(ROTOR_II[0],  ROTOR_II[1],  position=0),
            Rotor(ROTOR_III[0], ROTOR_III[1], position=0)
        ],
        reflector=Reflector(REFLECTOR_B),
        plugboard=Plugboard([('A', 'Z'), ('B', 'Y'), ('C', 'X')])
    )

    decrypted = "".join(machine.press_key(c) for c in encrypted)
    print(f"Decrypted: {decrypted}")


if __name__ == "__main__":
    main()
