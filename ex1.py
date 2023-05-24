from Cryptodome.Cipher import DES
from Cryptodome.Util.Padding import pad, unpad
import sys

# xor function - return the xor of the 3 bytes
def xor(a, b, c):
    return bytes([a ^ b ^ c])

# oracle function - return true if the padding is correct
def oracle(ciphertext, key, iv):
    try:
        cipher = DES.new(key, DES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), 8)
        return True
    except ValueError:
        return False

# decrypt function - return the plaintext after decrypting
def decrypt(ciphertext, key, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), 8)
    return plaintext

# attack_per_block function - return the decrypted block in hex
def attack_per_block(previousBlock, blockToDecrypt):
    Xj_Ci = bytes([0] * 8) + blockToDecrypt
    realText = [0, 0, 0, 0, 0, 0, 0, 0]
    for i in range(8):
        while True:
            for j in range(256):
                if oracle(Xj_Ci, key, iv):
                    break
                Xj_Ci = Xj_Ci[:7 - i] + bytes([Xj_Ci[7 - i] + 1]) + Xj_Ci[8 - i:]
            break

        last = xor(i + 1, previousBlock[(7 - i)], Xj_Ci[7 - i])
        realText[7 - i] = last

        for k in range(i + 1):
            var = xor(i + 2, previousBlock[(7 - k)], int(realText[7 - k].hex(), 16))
            Xj_Ci = Xj_Ci[:7 - k] + var + Xj_Ci[8 - k:]

    result = ''
    for item in realText:
        result += item.hex()

    return result

# main function :
if __name__ == '__main__':
    # check if the user entered 3 arguments
    if len(sys.argv) != 4:
        print("please enter this args: python3 ex1.py <ciphertext> <key> <iv> ")
        exit(1)
    ciphertext = bytes.fromhex(sys.argv[1])
    key = bytes(sys.argv[2].encode())
    iv = bytes.fromhex(sys.argv[3])

    decryptedText = ''
    # iterate over all the blocks
    for i in range(0, len(ciphertext), 8):
        if i == 0:
            decryptedText += attack_per_block(iv, ciphertext[:8])
        else:
            decryptedText += attack_per_block(ciphertext[i - 8:i], ciphertext[i:i + 8])
    # print the plaintext
    print(unpad(bytes.fromhex(decryptedText), 8).decode())
        
