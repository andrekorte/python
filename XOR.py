#!/usr/bin/env python

from os import urandom

def genkey(length):
    """Generate key"""
    return urandom(length)

def xor_strings(s,t):
    """xor two strings together"""
    if len(s) != len(t):
        print 'Message and key are of different length!'

    return "".join(chr(ord(a)^ord(b)) for a,b in zip(s,t))

# Create the message
message = 'This is a secret message'

# Create the key
key = genkey(len(message))

# Encrypt the message
ciphertext = xor_strings(message, key)
print 'ciphertext:', ciphertext

# Decrypt the ciphertext
print 'decrypted:', xor_strings(ciphertext,key)

# verify
if xor_strings(ciphertext, key) == message:
    print 'Unit test passed'
else:
    print 'Unit test failed'
