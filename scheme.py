#!/usr/bin/python

import re
import os
import base64
import struct
import sys
import traceback
from operator import xor
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util import Counter

nonce = 'c59bcf35'
ENCRYPTION_KEY = 'Sixteen byte key' 
STREAM_CIPHER_KEY = 'thiskeyisverybad' # it is 128 bits though
ENCRYPTION_KEY = 'Sixteen byte key'

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[:-ord(s[len(s)-1:])]

# Isolating words and not any punctuation marks
r_word = re.compile("(\w[\w']*\w|\w)")

xorWord = lambda ss,cc: ''.join(chr(ord(s)^ord(c)) for s,c in zip(ss,cc))

def nextWord(fileobj):
    for line in fileobj:
        for word in r_word.findall(line):
            yield word

def chunksplit(chunk, length):
    return (chunk[0+i:length+i] for i in range (0, len(chunk), length))

class Counter:
    def __init__(self, nonce):
        assert(len(nonce)==8)
        self.nonce = nonce
        self.cnt = 0

    def __call__(self):
        righthalf = struct.pack('>Q',self.cnt)
        self.cnt += 1
        return self.nonce + righthalf

#Random text for StreamCipher
plaintext = 'This is uuuuuuuu'

class StreamCipher:
    def __init__(self, key):
        self.skey = key

    def generate(self):
        cipher_ctr = AES.new(self.skey, mode=AES.MODE_CTR, counter=Counter(nonce))
        return cipher_ctr.encrypt(plaintext)   
    
    def decrypt(self, enc):
        cipher_ctr = AES.new(self.skey, mode=AES.MODE_CTR, counter=Counter(nonce))
        return cipher_ctr.decrypt(enc)

class AESCipher:
    def __init__(self, key):
        self.ekey = key

    def encrypt(self, raw):
        #raw = pad(raw)
        iv = plaintext
        cipher = AES.new(self.ekey, AES.MODE_CBC, iv)
        return cipher.encrypt(raw) 

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.ekey, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[16:]))

# The final scheme for encryption
def encryptionScheme():
    # Remove all encrypted files
    os.popen('find ./ciphertext/ -maxdepth 1 -type f -delete')
    stream_cipher = StreamCipher(STREAM_CIPHER_KEY)
    w_aes_cipher = AESCipher(ENCRYPTION_KEY)
    s_aes_cipher = AESCipher(ENCRYPTION_KEY)
    for filename in os.listdir("./raw/"):
        with open(os.path.join('./raw/', filename), 'rb') as in_file:
            with open(os.path.join('./ciphertext/', filename + '.enc'), 'wb') as out_file:
                for word in nextWord(in_file):
                    my_word = word.ljust(32, '.')
                    nBits = len(my_word)
                    EWi = w_aes_cipher.encrypt(my_word)
                    Si = stream_cipher.generate()
                    FiSi = s_aes_cipher.encrypt(Si)
                    Ti = Si + FiSi # lengh 282 
                    ciphertext = xorWord(EWi, Ti)
                    out_file.write(ciphertext)

# Search word
def searchScheme():
    while True:
        try:
            word2search = raw_input('\nEnter a word to search: ')
            if not word2search:
                print('Must enter some text to proceed')
                continue

            word2search_padded = word2search.ljust(32, '.') 
            w_aes_cipher = AESCipher(ENCRYPTION_KEY)
            s_aes_cipher = AESCipher(ENCRYPTION_KEY)

            cipher2search = w_aes_cipher.encrypt(word2search_padded)
            for filename in os.listdir('./ciphertext/'):
                success = 0
                with open(os.path.join('./ciphertext/', filename), 'rb') as in_file:
                    in_data = in_file.read(32)
                    while in_data:
                        Ti = xorWord(cipher2search, in_data)
                        Ti = list(chunksplit(Ti, 16))
                        if s_aes_cipher.encrypt(Ti[0]) == Ti[1]:
                            success = 1;
                            break
                        in_data = in_file.read(32)
                print ('Present in {0}'.format(filename) if success==1 else 'Not present in {0}'.format(filename))
        except EOFError:
            print ('\nQuitting...\n')
            sys.exit(0)
        except Exception as e:
            print(traceback.format_exc())

encryptionScheme()
searchScheme()
