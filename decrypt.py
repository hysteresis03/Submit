# pip install pycryptodome
# Exact inverse of the encryptor: strip the 4-byte length, DES-ECB decrypt,
# truncate to that length, write the original bytes back unchanged.
# usage: python3 decrypt_update.py <input_file> [output_file]
import os
import sys

try:
    from Crypto.Cipher import DES
except ImportError:
    from Cryptodome.Cipher import DES

if len(sys.argv) < 2:
    sys.exit("usage: python3 decrypt_update.py <input_file> [output_file]")

src = sys.argv[1]
dst = sys.argv[2] if len(sys.argv) > 2 else os.path.splitext(src)[0] + ".out"

k = bytearray(8)
for i, ch in enumerate(b"ib_lupt_enc", 1):
    k[i % 8] = (k[i % 8] + ch) & 0xFF

raw = open(src, "rb").read()
n = int.from_bytes(raw[-4:], "little")                 # original length
plain = DES.new(bytes(k), DES.MODE_ECB).decrypt(raw[:-4])[:n]

with open(dst, "wb") as f:                             # write bytes, do not re-encode
    f.write(plain)

print("wrote", dst, "-", len(plain), "bytes, length field =", n)