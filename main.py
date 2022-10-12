from diffie_hellman import *
from cbc import *
from hashlib import sha256
from copy import deepcopy

def setup_alice_and_bob():
  is_bytes = input(f'\n\nIs input in bytes (string) or int (default is int) [b|i] ? ')
  if is_bytes == 'b':
    isBytes = True
  else:
    isBytes = False

  # create Alice and Bob endpoints
  if isBytes:
    q = int.from_bytes(bytes(input(f'\n\nProvide the desired q (prime number): '), 'utf-8'), byteorder='big')
    alpha = int.from_bytes(bytes(input(f'Provide the desired alpha (primitive root of q): '), 'utf-8'), byteorder='big')
  else:
    q = int(input(f'\n\nProvide the desired q (prime number): '))
    alpha = int(input(f'Provide the desired alpha (primitive root of q): '))

  print(f'\n\nCreating Alice...')
  alice = Endpoint(q, alpha)
  print(f'Alice is created!\nAlice\'s private key: {alice.pr}\nAlice\'s public key: {alice.pu}')

  print(f'\n\nCreating Bob...')
  bob = Endpoint(q, alpha)
  print(f'Bob is created!\nBob\'s private key: {bob.pr}\nBob\'s public key: {bob.pu}')

  # exchanging public keys
  print(f'\n\nExchanging public keys...')
  alice.set_other_pu(bob.pu)
  bob.set_other_pu(alice.pu)
  print(f'Public keys exchanged!\nAlice has Bob\'s public key: {alice.other_pu}\nBob has Alice\'s public key: {bob.other_pu}')

  # generate secrets
  print(f'\n\nGenerating secrets...')
  alice_secret = alice.generate_secret()
  print(f'Alice\'s secret is {alice_secret}')
  bob_secret = bob.generate_secret()
  print(f'Bob\'s secret is {bob_secret}')

  if alice_secret == bob_secret:
    print(f'\n\nKey exchange was successful and the secrets match!\n\n')
    return alice, bob
  else:
    print(f'Key exchange was NOT successful.\nSomething went wrong\n\n')
    return None, None


def from_alice_to_bob(key, alice, bob):
  msg = input(f'\n\nInput Message Here: ')
  cbc = CBC(str(key))

  ct = cbc.encrypt(msg)
  print(f'\n\nAlice\'s encrypted message is: {ct}')

  ct = checkForTampering(alice, bob, ct)

  pt = cbc.decrypt(ct)
  print(f'\n\nAfter recieving the encrypted message, Bob decrypts it to be: \'{pt}\'\n\n')

def from_bob_to_alice(key, bob, alice):
  msg = input(f'\n\nInput Message Here: ')
  cbc = CBC(str(key))

  ct = cbc.encrypt(msg)
  print(f'\n\nBob\'s encrypted message is: {ct}')

  ct = checkForTampering(bob, alice, ct)

  pt = cbc.decrypt(ct)
  print(f'\n\nAfter recieving the encrypted message, Alice decrypts it to be: \'{pt}\'\n\n')


def malloryAlpha(ct, sender, receiver):
  print(f'\n\nSince Mallory has tampered with the alpha value or changed the public key, she can now read and write whatever she wants.')
  mallory = Endpoint(sender.q, sender.alpha)
  mallory.set_other_pu(receiver.pu)
  mallory.generate_secret()
  print(f'Mallory\'s generated secret: {mallory.secret}')

  cbc = CBC(str(mallory.secret))

  pt = cbc.decrypt(ct)

  print(f'Mallory reads the decrypted message as: {pt}')
  print(f'Mallory now sends the encrypted message of \'Mallory was here\' in place of the original.')

  return cbc.encrypt('Mallory was here')


def malloryPublicKey(ct):
  print(f'\n\nMallory knows that since she modified the public keys of both parties, their secrets are both 0.')

  cbc = CBC(str(0))

  pt = cbc.decrypt(ct)

  print(f'Mallory reads the decrypted message as: {pt}')
  print(f'Mallory now sends the encrypted message of \'Mallory was here\' in place of the original.')

  return cbc.encrypt('Mallory was here')


def checkForTampering(sender, reciever, ct) -> str:
  '''
  Returns the new ciphered text
  '''
  if sender.alpha == 1 or sender.alpha == sender.q or sender.alpha == sender.q-1:
    return malloryAlpha(ct, sender, reciever)
  elif sender.other_pu == sender.q:
    return malloryPublicKey(ct)
  return ct


def tamperPublicKeys(alice, bob):
  alice.other_pu = alice.q
  bob.other_pu = bob.q

  alice.generate_secret()
  bob.generate_secret()
  
  print(f'\n\nAfter Mallory has tampered with the public keys, these are now the secrets\nAlice\'s secret: {alice.secret}\nBob\'s secret: {bob.secret}\n\n')


def tamperAlphaTo1(alice, bob):
  alice.alpha = 1
  bob.alpha = 1
  alice.initialize_keys()
  bob.initialize_keys()
  alice.set_other_pu(bob.pu)
  bob.set_other_pu(alice.pu)

  alice.generate_secret()
  bob.generate_secret()
  
  print(f'\n\nAfter Mallory has tampered with the alpha value, these are now the secrets\nAlice\'s secret: {alice.secret}\nBob\'s secret: {bob.secret}\n\n')

def tamperAlphaToq(alice, bob):
  alice.alpha = alice.q
  bob.alpha = bob.q
  alice.initialize_keys()
  bob.initialize_keys()
  alice.set_other_pu(bob.pu)
  bob.set_other_pu(alice.pu)

  alice.generate_secret()
  bob.generate_secret()
  
  print(f'\n\nAfter Mallory has tampered with the alpha value, these are now the secrets\nAlice\'s secret: {alice.secret}\nBob\'s secret: {bob.secret}\n\n')


def tamperAlphaTo1LessThanq(alice, bob):
  alice.alpha = alice.q - 1
  bob.alpha = bob.q - 1
  alice.initialize_keys()
  bob.initialize_keys()
  alice.set_other_pu(bob.pu)
  bob.set_other_pu(alice.pu)

  alice.generate_secret()
  bob.generate_secret()
  
  print(f'\n\nAfter Mallory has tampered with the alpha value, these are now the secrets\nAlice\'s secret: {alice.secret}\nBob\'s secret: {bob.secret}\n\n')


def tamper(alice, bob):
  prompt = f'\n\n--- MALLORY TAMPER OPTIONS ---\n\n1 Tamper Alice and Bob\'s public keys equal to q\n2 Tamper the generator alpha to equal 1\n3 Tamper the generator alpha to equal q\n4 Tamper the generator alpha to equal one less than q\n5 Don\'t tamper anything\n\ncommand > '
  cmd = input(prompt)

  if cmd == '1':
    tamperPublicKeys(alice, bob)
  elif cmd == '2':
    tamperAlphaTo1(alice, bob)
  elif cmd == '3':
    tamperAlphaToq(alice, bob)
  elif cmd == '4':
    tamperAlphaTo1LessThanq(alice, bob)
  elif cmd == '5':
    pass
  else:
    print(f'Invalid command {cmd}.\nReturning to main menu...')


def main():
  print(f'\n\n--- WELCOME ---')

  alice, bob = setup_alice_and_bob()
  originalAlice = deepcopy(alice)
  originalBob = deepcopy(bob)

  if alice is None:
    return 

  while True:
    prompt = f'--- MAIN MENU ---\n\n1 Send encrypted message from Alice to Bob\n2 Send encrypted message from Bob to Alice\n3 Open Mallory\'s tamper options\n4 Reset tampered items\n5 Exit Program\n\ncommand > '
    cmd = input(prompt)

    if cmd == '1':
      from_alice_to_bob(alice.secret, alice, bob) 
    elif cmd == '2':
      from_bob_to_alice(bob.secret, bob, alice)
    elif cmd == '3':
      tamper(alice, bob)
    elif cmd == '4':
      alice.alpha = originalAlice.alpha
      alice.pu = originalAlice.pu
      alice.pr = originalAlice.pr
      alice.other_pu = originalAlice.other_pu
      alice.secret = originalAlice.secret

      bob.alpha = originalBob.alpha
      bob.pu = originalBob.pu
      bob.pr = originalBob.pr
      bob.other_pu = originalBob.other_pu
      bob.secret = originalBob.secret

      print(f'\n\nReset complete!\n\n')

    elif cmd == '5':
      return 
    else:
      print(f'Invalid command {cmd}.')


if __name__=='__main__':
  main()
