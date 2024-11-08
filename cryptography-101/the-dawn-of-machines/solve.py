import itertools
import sys
from enigma.machine import EnigmaMachine

res = []

c = 'tzfx[iljt iab dkvr fif ujdznn rz vvc tvamydhr...]'
c_modified = "".join(ch for ch in 'tzfx iljt iab dkvr fif ujdznn rz vvc tvamydhr' if ch != " ").upper()


def attack():
    def brute_ring_settings(ciphertext):
        for rotors in itertools.permutations(["I", "II", "III", "IV", "V", "VI", "VII", "VIII"], 3):
            rotors = list(rotors)
            for a in range(0, 26):
                for b in range(0, 26):
                    for c in range(0, 26):
                        machine = EnigmaMachine.from_key_sheet(
                            rotors=rotors,
                            reflector='B',
                            ring_settings=[a, b, c],
                            plugboard_settings='as dt uq ew gj of xz bn py vk')
                        plaintext = machine.process_text(ciphertext)
                        print(rotors, a, b, c, plaintext)
                        if plaintext.startswith('FLAG'):
                            print('[+] Ring settings: {}, {}, {}'.format(a, b, c))
                            res.append((a, b, c))
        return -1, -1, -1

    # a, b, c = brute_ring_settings('IPUXZGICZWASMJFGLFVIHCAYEGT')
    a, b, c = brute_ring_settings(c_modified)
    print(res)

    if a < 0 or b < 0 or c < 0:
        print('[-] Failed')
        sys.exit(0)

    machine = EnigmaMachine.from_key_sheet(
        rotors='I II III',
        reflector='B',
        ring_settings=[a, b, c],
        plugboard_settings='AV BS CG DL FU HZ IN KM OW RX')

    plaintext = machine.process_text(c_modified.upper())
    print('[+] Flag: ' + plaintext)


possible = [(3, 6, 4), (12, 11, 0), (18, 2, 12), (1, 25, 22), (4, 24, 6), (9, 16, 6), (6, 25, 6), (25, 6, 0),
            (14, 3, 20), (0, 15, 6), (4, 20, 11)]


def decode(ciphertext, a, b, c):
    for rotors in itertools.permutations(["I", "II", "III", "IV", "V", "VI", "VII", "VIII"], 3):
        rotors = list(rotors)
        machine = EnigmaMachine.from_key_sheet(
            rotors=rotors,
            reflector='B',
            ring_settings=[a, b, c],
            plugboard_settings='as dt uq ew gj of xz bn py vk')
        plaintext = machine.process_text(ciphertext)
        if plaintext.startswith('FLAG'):
            print('[+] Ring settings: {}, {}, {}, {}'.format(rotors, a, b, c))
            print('flag:', plaintext)
            res.append((a, b, c))


for a, b, c in possible:
    decode(c_modified, a, b, c)
