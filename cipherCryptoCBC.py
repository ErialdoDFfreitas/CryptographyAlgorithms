#%%
import json

#%% Encrypt
from base64 import  b64encode
from Crypto.Cipher import AES #Salsa20
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

data = b"secret"
key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CBC)
ct_bytes = cipher.encrypt(pad(data, AES.block_size))
iv = b64encode(cipher.iv).decode('utf-8')
ct = b64encode(ct_bytes).decode('utf-8')
result = json.dumps({'iv':iv, 'ciphertext':ct})
print(result)

#%%Decrypt
from base64 import  b64decode
from Crypto.Cipher import AES #Salsa20
from Crypto.Util.Padding import unpad

try:
    b64 = json.loads(result)#json_input)
    iv = b64decode(b64['iv'])
    ct = b64decode(b64['ciphertext'])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    print("The message is: ", pt)
except (ValueError, KeyError):
    print("Incorrect decryption")





'''#key = b'012345678'
key = get_random_bytes(16)

#cipher = Salsa20.new(key)
cipher = AES.new(key, AES.MODE_CBC)

cipherText = cipher.encrypt(b'The secret I want to send')
cipherText += cipher.encrypt(b'The second part of the secret.')

print(cipher.nonce)'''


# %%
