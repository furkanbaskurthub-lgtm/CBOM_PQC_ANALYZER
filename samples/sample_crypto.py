import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
sha = hashlib.sha256(b"hello world").hexdigest()
md5 = hashlib.md5(b"legacy").hexdigest()

key = b"0123456789abcdef0123456789abcdef"
iv = b"0123456789abcdef"
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
