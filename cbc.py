from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from hashlib import sha256

class CBC:
  def __init__(self, key: str):
    self.key = sha256(key.encode('utf-8')).digest()
    self.encrypt_cipher = AES.new(self.key, AES.MODE_CBC)
    self.iv = None
    self.decrypt_cipher = None

  def encrypt(self, pt):
    ct_bytes = self.encrypt_cipher.encrypt(pad(pt.encode('utf-8'), AES.block_size))

    self.iv = self.encrypt_cipher.iv

    return b64encode(self.iv + ct_bytes).decode('utf-8')

  def decrypt(self, ct):
    try:
      ct = b64decode(ct)
      self.decrypt_cipher = AES.new(self.key, AES.MODE_CBC, ct[:AES.block_size])
      return unpad(self.decrypt_cipher.decrypt(ct[AES.block_size:]), AES.block_size).decode('utf-8')
    except (ValueError, KeyError) as e:
      print(f'Encountered an error during decryption.\n{e}')
      raise Exception()
