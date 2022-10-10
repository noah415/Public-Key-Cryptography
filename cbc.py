from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

class CBC:
  def __init__(self, key):
    self.key = key
    self.encrypt_cipher = AES.new(self.key, AES.MODE_CBC)
    self.iv = None
    self.decrypt_cipher = None

  def encrypt(self, pt):
    ct_bytes = self.encrypt_cipher.encrypt(pad(pt, AES.block_size))

    self.iv = self.encrypt_cipher.iv

    return b64encode(ct_bytes).decode('utf-8')

  def decrypt(self, ct):
    if self.decrypt_cipher is None:
      if self.iv is None:
        print(f'Must encrypt before attempting to decrypt the message.')
        raise Exception()

      self.decrypt_cipher = AES.new(self.key, AES.MODE_CBC, self.iv)

    try:
      ct = b64decode(ct)
      return unpad(self.decrypt_cipher.decrypt(ct, AES.MODE_CBC, self.iv))
    except (ValueError, KeyError) as e:
      print(f'Encountered an error during decryption.\n', e)
