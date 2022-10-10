from diffie_hellman import *
from cbc import *

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


def from_alice_to_bob():
  pass


def from_bob_to_alice():
  pass


def main():
  print(f'\n\n--- WELCOME ---')

  alice, bob = setup_alice_and_bob()

  if alice is None:
    return 
  
  while True:
    prompt = f'1 Send encrypted message from Alice to Bob\n2 Send encrypted message from Bob to Alice\n3 Exit program\n\ncommand > '
    cmd = input(prompt)

    if cmd == '1':
      pass
    elif cmd == '2':
      pass
    elif cmd == '3':
      return 
    else:
      print(f'Invalid command {cmd}.')


if __name__=='__main__':
  main()
