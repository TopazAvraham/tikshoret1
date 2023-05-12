from Cryptodome.Cipher import DES
from Cryptodome.Util.Padding import pad, unpad
def xor(a, b, c):
  return bytes([a ^ b ^ c])

#step6
def oracle(ciphertext,key ,iv):
  try:
    cipher = DES.new(key, DES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), 8)
    return True
  except:
    return False
def decrypt(ciphertext,key ,iv):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), 8)
    return plaintext
text = b"Hello World"
key = b"mydeskey"
iv = bytes([0] * 8)

#step 2
# print(pad(text, 8))

#step 3
cipher = DES.new(key, DES.MODE_CBC, iv)

ciphertext = cipher.encrypt(pad(text, 8))
#print(ciphertext.hex())
#step 4
cipher = DES.new(key, DES.MODE_CBC, iv)
plaintext= unpad(cipher.decrypt(ciphertext), 8)
#print(plaintext)

#step 5
# print(xor(0,0,0))
# print(xor(0,0,1)) 
# print(xor(0,1,0)) 
# print(xor(0,1,1)) 
# print(xor(1,0,0)) 
# print(xor(1,0,1)) 
# print(xor(1,1,0)) 
# print(xor(1,1,1))

#step 6
# print(oracle(ciphertext,key,iv))
# print(oracle("12345678".encode(),key,iv))

#step 7 
# take the second block of the ciphertext
c = bytes([0] * 8) + ciphertext[8:16]

for i in range(8):
    while True:
        for j in range(255):
            if oracle(c,key,iv): 
                break
        
            c = c[:7-i] + bytes([c[7-i] + 1]) + c[8-i:]
        break
    plaintag = decrypt(c,key,iv)

    lastPlainTextByte = xor(i+1,ciphertext[7-i] ,c[7-i])
    print(lastPlainTextByte.hex())
    var = xor(i+2,ciphertext[7-i] ,int(lastPlainTextByte.hex(),16))
    c = c[:7-i] + var + c[8-i:]
    



