import math, random
from Crypto.Util import number

class RSA:

    def __init__(self, bitcount, bitcount_floor=4):
        # self.low_prime_list = self._sieve_of_eratosthenes(100000000)
        self.bitcount = bitcount
        self.bitcount_floor = bitcount_floor
        self.e = 65537

        if self.bitcount < self.bitcount_floor:
            print(f'Minimum bitcount is {self.bitcount_floor} but bitcount of {self.bitcount} requested. ' + \
                f'Setting bitcount to {self.bitcount_floor + 1} bit minimum')
            self.bitcount = self.bitcount_floor + 1

        
        self._generate_key_components()
        self._set_crt_components()

    def public_key(self):
        return self._encrypt_message

    def _encrypt_message(self, text: str):
        int_str = self._text_to_int(text)
        return (int_str ** self.e) % self.n

    def private_key(self):
        return self._decrypt_message
        
    def _decrypt_message(self, message: int):

        # print('Decrypting')
        # int_str = (message ** self._d) % self.n

        print(f'Starting decryption (this may take a while)...')
        m_1 = pow(message, self._dp) % self._p
        print(f'Calculated m_1...')
        m_2 = pow(message, self._dq) % self._q
        print(f'Calculated m_2...')
        h = (self._q_inv * (m_1 - m_2)) % self._p
        print(f'Calculated h...')

        int_str = m_2 + h * self._q
        print(f'Calculated message...')

        return self._int_to_text(int_str)

    def _text_to_int(self, text):
        hex_str = text.encode('utf-8').hex()
        print(hex_str)
        int_text = int(hex_str, 16)
        return int_text

    def _int_to_text(self, number):
    
        hex_num = hex(number)
        if hex_num[0:2] == '0x':
            hex_num = hex_num[2:]

        return bytes.fromhex(hex_num).decode('utf-8')


    def _generate_key_components(self):
        self._p, self._q = self._get_prime_numbers()
        self.n = self._p * self._q

        m = math.lcm((self._p - 1), (self._q - 1))

        # inverse mod
        self._d = pow(self.e, -1, m)

        self._dp = self._d % (self._p - 1)
        self._dq = self._d % (self._q - 1)     

    def _set_crt_components(self):
        self._dp = self._d % (self._p - 1)
        self._dq = self._d % (self._q - 1)
        self._q_inv = pow(self._q, -1, self._p)

    def _get_prime_numbers(self):
         return (number.getPrime(random.randrange(self.bitcount_floor, self.bitcount)),
                number.getPrime(random.randrange(self.bitcount_floor, self.bitcount)))

    # def _find_mod_inverse(self, a, m):
    #     if math.gcd(a, m) != 1:
    #         return None
    #     u1, u2, u3 = 1, 0, a
    #     v1, v2, v3 = 0, 1, m
   
    #     while v3 != 0:
    #         q = u3 // v3
    #         v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    #     return u1 % m



'''
THE CODE BELOW IS FOR GENERATION OF LARGE PRIMES AND TAKES FOREVER TO RUN. DO NOT USE.
'''



    # def _get_prime_number(self):

    #     valid_candidate = False

    #     while not valid_candidate:

    #         candidate = (random.randrange(2**(self.bitcount-1)+1, 2**self.bitcount-1))

    #         if self._low_prime_check(candidate) and self._miller_rabin_test(candidate, 20):
    #             return candidate

    # def _low_prime_check(self, prime_candidate):
    #     for divisor in self.low_prime_list: 
    #         if prime_candidate % divisor == 0 and divisor**2 <= prime_candidate:
    #             return 0
        
    #     # If no divisor found, return value
    #     return prime_candidate

    # def _miller_rabin_test(self, prime_candidate, trials):

    #     # FACTORIZATION
    #     exp = prime_candidate - 1
    #     divisions = 0

    #     while exp % 2 == 0:
    #         # equivalent to exp // 2 but faster
    #         exp >>= 1
    #         divisions += 1

    #     '''
    #     MILLER RABIN TRIAL RUN START
    #     '''
    #     def _miller_trial_run_failed(a):
    #         if pow(a, exp, prime_candidate) == 1:
    #             return False

    #         for i in range(divisions):
    #             if pow(a, 2**i * exp, prime_candidate) == 1:
    #                 return False

    #         return True
    #     '''
    #     MILLER RABIN TRIAL RUN END
    #     '''

    #     # run miller rabin trials
    #     for i in range(trials):
    #         if _miller_trial_run_failed(random.randrange(2, prime_candidate)):
    #             return False
    #     return True

    # def _sieve_of_eratosthenes(self, n):
    
    #     # Create a boolean array
    #     # "prime[0..n]" and initialize
    #     # all entries it as true.
    #     # A value in prime[i] will
    #     # finally be false if i is
    #     # Not a prime, else true.
    #     # effective/fast generation of primes up to 1 mil.
    #     prime = [True for i in range(n+1)]
    #     p = 2
    #     while (p * p <= n):
     
    #         # If prime[p] is not
    #         # changed, then it is a prime
    #         if (prime[p] == True):
     
    #             # Update all multiples of p
    #             for i in range(p * p, n+1, p):
    #                 prime[i] = False
    #         p += 1
     
    #     return [i for i, p in enumerate(prime) if p][2:]

rsa = RSA(16)

message = rsa.public_key()("A")
message2 = rsa.public_key()("64")
print(f'Encrypted messages: {message}, {message2}')
print(rsa.private_key()(message))
print(rsa.private_key()(message2))
