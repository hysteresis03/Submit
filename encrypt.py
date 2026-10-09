# pip install pycryptodome
from Crypto.Cipher import DES

k = bytearray(8)
for i, ch in enumerate(b"ib_lupt_enc", 1):
    k[i % 8] = (k[i % 8] + ch) & 0xFF
print("key:", k.hex(" "))

plain = open(r"/home/johnwick/Shell/update.ept.unc", "rb").read()   # raw bytes, keep the UTF-16 BOM
n = len(plain)

pad = (-n) % 8                                         # pad up to a multiple of 8
enc = DES.new(bytes(k), DES.MODE_ECB).encrypt(plain + b"\x00" * pad)

open(r"/home/johnwick/mitm/update.ept", "wb").write(enc + n.to_bytes(4, "little"))
print("wrote", len(enc) + 4, "bytes, length field =", n)
