from math import gcd, pow
import random

class Endpoint:
  def __init__(
    self,
    q,
    alpha,
  ):
    self.q = q
    self.alpha = alpha
    self.pr = 0
    self.pu = 0
    self.other_pu = 0
    self.secret = 0

    self.generate_private_key()
    self.generate_public_key()

  def generate_private_key(self):
    coprime = random.randint(1, self.q)

    while gcd(coprime, self.q) != 1:
      coprime = random.randint(1, self.q)
    
    self.pr = coprime
  
  def generate_public_key(self):
    if self.pr < 1 or self.pr >= self.q:
      raise Exception(f'Something went wrong when generating the private key: {self.pr}')

    self.pu = pow(self.alpha, self.pr) % self.q

  def set_other_pu(self, other_pu):
    if other_pu < 1 or other_pu >= self.q:
      raise Exception(f'Invalid other public key: {other_pu}')

    self.other_pu = other_pu

  def generate_secret(self):
    if self.other_pu == 0:
      print('Could not generate secret without an outsider\'s public key')
      raise Exception()

    self.secret = pow(self.other_pu, self.pr) % self.q
    return self.secret