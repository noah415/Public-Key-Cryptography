from diffie_hellman import *
from cbc import *

def main():
  print(f'--- WELCOME ---')

  # create Alice and Bob endpoints
  q = input('Provide the desired q (prime number): ')
  alpha = input('Provide the desired alpha (primitive root of q): ')

  print(f'Creating Alice ...')
  alice = Endpoint(q, alpha)
  print(f'Alice is created!\nAlice\'s private key: {alice.pr}\nAlice\'s public key: {alice.pu}')

  print(f'Creating Bob...')
  bob = Endpoint(q, alpha)
  print(f'Bob is created!\nBob\'s private key: {bob.pr}\nBob\'s public key: {bob.pu}')

  # exchanging public keys
  print(f'Exchanging public keys ...')
  alice.set_other_pu(bob.pu)
  bob.set_other_pu(alice.pu)
  print(f'Public keys exchanged!\nAlice has Bob\'s public key: {alice.other_pu}\nBob has Alice\'s public key: {bob.other_pu}')

  # generate secrets
  print(f'Generating secrets ...')
  alice_secret = alice.generate_secret()
  print(f'Alice\'s secret is {alice_secret}')
  bob_secret = bob.generate_secret()
  print(f'Bob\'s secret is {bob_secret}')

  if alice_secret == bob_secret:
    print(f'Key exchange was successful and the secrets match!')
  else:
    print(f'Key exchange was NOT successful.\nSomething went wrong')


if __name__=='__main__':
  main()
