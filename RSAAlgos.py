from math import sqrt

def gcd(a,b):
  assert a >= 0 and b >= 0
  while a > 0 and b > 0:
    if a > b:
      a = a% b
    else:
      b = b % a 
  return max(a,b)
  
  
def lcm(a, b):
  d = gcd(a,b)
  return int(a*b / d)
  
  
def matricialProduct(a,b):
  result = [[0,0],[0,0]]
  for i in range(len(a)):
    for j in range(len(b[0])):
      for k in range(len(b)):
        result[i][j] += a[i][k] * b[k][j]
  return result
  
  
def diophantine(a, b, c):
  q, re = gcd(a,b)
  assert c % q == 0
  queues = []
  for i in range(len(re)):
    queues.append([[re[i],1],[1,0]])
  mat = [[1,0],[0,1]]
  for i in range(len(queues)):
    mat = matricialProduct(mat, queues[i]).copy()
  if len(re) % 2:
    signe = -1
  else:
    signe = 1
  p = c // q
  if a >=b:
    x = mat[1][1]
    y = -mat[0][1]
  else:
    y = mat[1][1]
    x = -mat[0][1]
  return signe*x*p, signe*y*p
  

def ChineseRemainderTheorem(n1, r1, n2, r2):
  (x, y) = ExtendedEuclid(n1, n2)
  n = (r2*x*n1  + r1*y*n2) % (n1*n2) 
  return  n
  
def ModPowerTwo(b, e, m):
  if e == 0:
    c = 1
  else:
    c = b % m
  while e > 1:
    c = (c * c) % m
    e = e // 2
  return c

#You are given the function FastModularExponentiation(b, e, m) which computes b^e mod m
#(incorrectly) using "e" modular multiplications. You need to change this implementation
#to work significantly faster, return correct result and use only around 2log_2(e) modular multiplications.

def FastModularExponentiation(b, e, m):
  eBin = int(format(e, "b"))
  c = 1
  two = 1
  while eBin > 0:
    currentE = eBin % 10 
    if currentE != 0:
      c = (c*ModPowerTwo(b,two**currentE, m)) % m
    two = two*2
    eBin = eBin // 10
  return c
  
#You have access to the function PowMod(a, n, modulo)which computes a^n mod(modulo)
#using the fast modular exponentiation algorithm from the previous module. You also have 
#access to the function ConvertToInt(message) which converts a text message to an integer.
#You need to fix the implementation of the function Encrypt(message, modulo, exponent) to 
#return the integer ciphertextciphertext according to RSA encryption algorithm.


def Encrypt(message, modulo, exponent):
  # Fix this implementation
  return PowMod(ConvertToInt(message), exponent, modulo)  
  
  
#You have access to the function ConvertToStr(m) which converts from integer m to the plaintext message.
#You also have access to the function InvertModulo(a, n) which takes coprime integers "a" and "n" as inputs 
#and returns integer "b" such that ab ≡ 1 mod n. You also have access to the function PowMod(a, n, modulo)
#which computes a^n mod(modulo) using fast modular exponentiation.
#You need to fix the implementation of the function Decrypt(ciphertext, p, q, exponent) to decrypt the message
#which was encrypted using the public key (n=p⋅q , e=exponent).
  
def Decrypt(ciphertext, p, q, exponent):
  d = InvertModulo(exponent,(p-1)*(q-1))
  return ConvertToStr(PowMod(ciphertext, d, p*q))
  
  
  
def DecipherSimple(ciphertext, modulo, exponent, potential_messages):
  # Fix this implementation
  for i in range(len(potential_messages)):
    if ciphertext == Encrypt(potential_messages[i], modulo, exponent):
      return potential_messages[i]
  return "don't know"
  
  

#DecipherSmallPrime(ciphertext,modulo,exponent), and you need to fix its implementation so that 
#it can decipher the ciphertextciphertext in case when one of the prime factors of the public modulo 
#is smaller than 1000000.

def DecipherSmallPrime(ciphertext, modulo, exponent):
  for i in range(2, int(sqrt(1000000))):
    if modulo % i == 0:
      small_prime = i
      big_prime = modulo // i
      return Decrypt(ciphertext, small_prime, big_prime, exponent)
  return "dont't know"


#DecipherSmallDiff(ciphertext,modulo,exponent), and you need to fix its implementation so that it 
#can decipher the ciphertext in case when the difference beteween prime factors of the public modulo 
#is smaller than 5000.

def DecipherSmallDiff(ciphertext, modulo, exponent):
  sqrtN = IntSqrt(modulo)
  diff = sqrtN - 5000
  small_prime = 1
  big_prime = 1
  for i in range(diff, sqrtN+1):
    if modulo % i == 0:
      small_prime = i
      big_prime = modulo // small_prime
  return Decrypt(ciphertext, small_prime, big_prime, exponent)
  
  
#You need to fix its implementation so that it can decipher both first_ciphertext and second_ciphertext 
#in case when first_modulo and second_modulo share a prime factor.
  
def DecipherCommonDivisor(first_ciphertext, first_modulo, first_exponent, second_ciphertext, second_modulo, second_exponent):
  p = GCD(first_modulo, second_modulo)
  q1 = first_modulo // p
  q2 = second_modulo // p
  return (Decrypt(first_ciphertext, p, q1, first_exponent), Decrypt(second_ciphertext, p, q2, second_exponent))


#Fix the implementation of the function DecipherHastad(first_ciphertext,first_modulo,second_ciphertext,second_modulo)
#to return the message that Bob has encrypted and sent.

def DecipherHastad(first_ciphertext, first_modulo, second_ciphertext, second_modulo):
  # Fix this implementation
  c = ChineseRemainderTheorem(first_modulo, first_ciphertext, second_modulo, second_ciphertext)
  
  
  return ConvertToStr(IntSqrt(c))
