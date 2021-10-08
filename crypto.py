from Crypto.Cipher import DES
from Crypto.Cipher import DES3
from Crypto import Random
from Crypto.Util import number 
import hashlib
from math import sqrt  
from sympy import * 
import base64
import os 
import random
from hashlib import blake2b
import binascii
from Crypto.Random import get_random_bytes

class Encrpytion:
    #final_key=0

    def findPrimefactors(s, n): 
        while(n % 2 == 0): 
            s.add(2)  
            n = n // 2
        for i in range(3, int(sqrt(n)), 2): 
            while (n % i == 0) :   
                s.add(i)  
                n = n // i  
          
        if (n > 2) : 
            s.add(n)  

  
    def findPrimitive(n) : 
        s = set()  
        if(isprime(n) == False):  
            return -1
        phi = n - 1
        Encrpytion.findPrimefactors(s, phi)  
        for r in range(2, phi + 1):  
            flag = False
            for it in s:  
                if (pow(r, phi // it, n) == 1):  
                    flag = True
                    break
            if (flag == False): 
                return r  
        return -1
     

    def pad(text):
        while len(text)%8 != 0:
            text += ' ' 	
        return text


    def encrypt_message(self,key,mssge):
        iv = os.urandom(8)
        cipher_encrypt = DES3.new(key, DES3.MODE_OFB, iv)
        encrypted_mssge = cipher_encrypt.encrypt(bytes(mssge,'utf-8'))
        encrypted_mssge = iv+encrypted_mssge
        return binascii.hexlify(encrypted_mssge)

    def decrypt_message(self,key,encrypted_mssge):
        encrypted_mssge = binascii.unhexlify(encrypted_mssge)
        iv = encrypted_mssge[:8] 
        encrypted_mssge = encrypted_mssge[8:]
        cipher_decrypt = DES3.new(key, DES3.MODE_OFB, iv)
        decrypted_mssge = cipher_decrypt.decrypt(encrypted_mssge)
        return  decrypted_mssge

    def diffiehellman1(self,large_primenum,rollnum):
        #global final_key
        generator_of_primenum = Encrpytion.findPrimitive(large_primenum)
        secret_key = number.getRandomNBitInteger(4)
        secret_key = str(secret_key)+str(rollnum)
        sha_key=hashlib.sha256(secret_key.encode())
        final_key=sha_key.hexdigest()
        final_key=int(final_key,16)
        return pow(generator_of_primenum,final_key,large_primenum), final_key
        

    def diffiehellman2(self,recieved_key,large_primenum,final_key):
        secret_key = str(pow(recieved_key,final_key,large_primenum))
        h = blake2b(digest_size=4)
        h.update(secret_key.encode())
        secret_key = h.hexdigest()
        return secret_key
 

    def encrypt_file(self,input_file,out_file,key):

        chunksize = 1024
        iv=os.urandom(8)	
        encryptor=DES3.new(key,DES3.MODE_OFB,iv)
        with open(input_file,'rb') as f:
            with open(out_file,'ab')as of:
                of.write(iv)
                while True:
                    chunk=f.read(1024)
                    if not chunk:
                        break
                    of.write(binascii.hexlify(encryptor.encrypt(chunk)))
                    
    

    def decrypt_file(self,input_file,out_file,key):
        with open(input_file,'rb') as f:
            iv=f.read(8)
            decryptor=DES3.new(key,DES3.MODE_OFB,iv)
            with open(out_file,'ab')as of:
                while True:
                    chunk=binascii.unhexlify(f.read(1024))
                    if len(chunk)==0:
                        break
                    of.write(decryptor.decrypt(chunk))



    def getPrime(self):
        return number.getPrime(8)

