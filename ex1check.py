from Cryptodome.Cipher import DES
from Cryptodome.Util.Padding import pad, unpad



def xor(a, b, c):
    return bytes([a ^ b ^ c])


# step6
def oracle(ciphertext, key, iv):
    try:
        cipher = DES.new(key, DES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), 8)
        return True
    except ValueError:
        return False


def decrypt(ciphertext, key, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), 8)
    return plaintext


text = b"Hello World"
key = b"mydeskey"
iv = bytes([0] * 8)

# step 3
cipher = DES.new(key, DES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(text, 8))
print("ciphertext in hex is: ",ciphertext.hex())
print("key in hex is: ",key.hex())
print("iv in hex is: ",iv.hex())
# do the same for the next block
def attack_per_block(previousBlock, blockToDecrypt, isLastBlock):
    c = bytes([0] * 8) + blockToDecrypt
    realText = [0, 0, 0, 0, 0, 0, 0, 0]
    for i in range(8):
        while True:
            for j in range(256):
                if oracle(c, key, iv):
                    break
                c = c[:7 - i] + bytes([c[7 - i] + 1]) + c[8 - i:]
            break
        
        last = xor(i + 1, previousBlock[(7 - i)], c[7 - i])
        realText[7 - i] = last

        for k in range(i + 1):
            var = xor(i + 2, previousBlock[(7 - k)], int(realText[7 - k].hex(), 16))
            c = c[:7 - k] + var + c[8 - k:]

    result = ''
    for item in realText:
        result += item.hex()

    return result

dycryptedText = ''
# itertate over all the blocks
for i in range(0, len(ciphertext), 8):
    if i == 0:
        dycryptedText += attack_per_block(iv, ciphertext[:8], i == len(ciphertext) - 8)
    else:
        dycryptedText += attack_per_block(ciphertext[i - 8:i], ciphertext[i:i + 8], i == len(ciphertext) - 8)

print(unpad(bytes.fromhex(dycryptedText), 8).decode())


