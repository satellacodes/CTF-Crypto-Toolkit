
import argparse
import base64
import sys
from itertools import cycle

from Crypto.Util.number import (GCD, bytes_to_long, inverse, isPrime,
                                long_to_bytes)


def solve_base(data: str, btype: str, decode: bool):
    try:
        if decode:
            mapping = {'b64': base64.b64decode, 'b32': base64.b32decode, 'b16': base64.b16decode}
            res = mapping[btype](data)
        else:
            mapping = {'b64': base64.b64encode, 'b32': base64.b32encode, 'b16': base64.b16encode}
            res = mapping[btype](data.encode())
        print(res.decode(errors='ignore'))
    except Exception as e:
        print(f"[!] Base {btype} { 'decode' if decode else 'encode' } failed: {e}")
        print_manual('base')

def solve_caesar(text: str, shift=None):
    alph = 'abcdefghijklmnopqrstuvwxyz'
    def shift_text(s, sh): return ''.join(alph[(alph.index(c.lower())-sh)%26] if c.lower() in alph else c for c in s)
    if shift is not None:
        print(shift_text(text, shift))
    else:
        for s in range(26):
            print(f"Shift {s}: {shift_text(text, s)}")

def solve_rot(text: str, n: int):
    # ROT-n is just Caesar with fixed shift
    solve_caesar(text, shift=n)

def solve_vigenere(cipher: str, key: str):
    alph = 'abcdefghijklmnopqrstuvwxyz'
    plain = []
    ki=0
    for c in cipher:
        if c.lower() in alph:
            pi = (alph.index(c.lower()) - alph.index(key[ki%len(key)].lower()))%26
            plain.append(alph[pi])
            ki+=1
        else:
            plain.append(c)
    print(''.join(plain))

def solve_xor(hexdata: str):
    data = bytes.fromhex(hexdata)
    results = []
    for k in range(256):
        text = ''.join(chr(b^k) if 32<= (b^k) <127 else '.' for b in data)
        results.append((k, text))
    for k, t in results:
        print(f"Key {k}: {t}")

def solve_affine(cipher: str):
    alph = 'abcdefghijklmnopqrstuvwxyz'
    data = cipher.lower()
    for a in range(1,26,2):
        if GCD(a,26)!=1: continue
        inv = inverse(a,26)
        for b in range(26):
            plain=''
            for c in data:
                if c in alph:
                    pi = (inv*(alph.index(c)-b))%26
                    plain+=alph[pi]
                else:
                    plain+=c
            print(f"a={a}, b={b}: {plain}")

def solve_rsa(n, e=None, d=None, c=None):
    if d and c:
        m = pow(c, d, n)
        print(long_to_bytes(m))
    elif e and c:
        # try to factor n (small)
        for p in range(2, int(n**0.5)+1):
            if n%p==0:
                q=n//p
                phi=(p-1)*(q-1)
                dcalc = inverse(e,phi)
                msg = long_to_bytes(pow(c, dcalc, n))
                print(msg)
                return
        print("[!] Failed to factor n")
        print_manual('rsa')
    else:
        print_manual('rsa')

def solve_hash(text: str, algorithm: str):
    import hashlib
    mapping = { 'md5':hashlib.md5, 'sha1':hashlib.sha1,'sha256':hashlib.sha256 }
    h = mapping.get(algorithm)
    if h:
        print(h(text.encode()).hexdigest())
    else:
        print_manual('hash')

def print_manual(topic):
    manuals = {
        'base': "Manual: Learn about Python's base64 module or use CyberChef: https://gchq.github.io/CyberChef/",
        'rsa': "Manual: Factor small RSA n using ECM or online tools, then compute d = e^-1 mod phi(n)",
        'hash': "Manual: Use hashcat or John the Ripper and wordlists to crack hashes",
    }
    print(manuals.get(topic, 'No manual available.'))

def main():
    parser = argparse.ArgumentParser(description='CTF Crypto Toolkit')
    sub = parser.add_subparsers(dest='mode')
    # base
    p_base = sub.add_parser('base')
    p_base.add_argument('--type', choices=['b64','b32','b16'], required=True)
    p_base.add_argument('--decode', action='store_true')
    p_base.add_argument('--input', required=True)
    # caesar
    p_c = sub.add_parser('caesar')
    p_c.add_argument('--input', required=True)
    p_c.add_argument('--shift', type=int)
    p_c.add_argument('--bruteforce', action='store_true')
    # rot
    p_r = sub.add_parser('rot')
    p_r.add_argument('--input', required=True)
    p_r.add_argument('--n', type=int, required=True)
    # vigenere
    p_v = sub.add_parser('vigenere')
    p_v.add_argument('--input', required=True)
    p_v.add_argument('--key', required=True)
    # xor
    p_x = sub.add_parser('xor')
    p_x.add_argument('--bruteforce', action='store_true')
    p_x.add_argument('--input', required=True, help='hex string')
    # affine
    p_a = sub.add_parser('affine')
    p_a.add_argument('--input', required=True)
    # rsa
    p_rsa = sub.add_parser('rsa')
    p_rsa.add_argument('--n', type=int, help='modulus')
    p_rsa.add_argument('--e', type=int, help='public exponent')
    p_rsa.add_argument('--d', type=int, help='private exponent')
    p_rsa.add_argument('--c', type=int, help='ciphertext')
    # hash
    p_h = sub.add_parser('hash')
    p_h.add_argument('--input', required=True)
    p_h.add_argument('--alg', choices=['md5','sha1','sha256'], required=True)

    args=parser.parse_args()
    if args.mode=='base': solve_base(args.input, args.type, args.decode)
    elif args.mode=='caesar':
        if args.bruteforce: solve_caesar(args.input)
        else: solve_caesar(args.input, shift=args.shift)
    elif args.mode=='rot': solve_rot(args.input, args.n)
    elif args.mode=='vigenere': solve_vigenere(args.input, args.key)
    elif args.mode=='xor': solve_xor(args.input)
    elif args.mode=='affine': solve_affine(args.input)
    elif args.mode=='rsa': solve_rsa(args.n, args.e, args.d, args.c)
    elif args.mode=='hash': solve_hash(args.input, args.alg)
    else: parser.print_help()

if __name__=='__main__': main()
