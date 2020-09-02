#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Este script toma como entrada un archivo RSA de clave pública, lo decodifica extrayendo el modulus y el exponente y genera la clave privada si es posible encontrar los primos del modulus, que se buscan online en https://www.numberempire.com/numberfactorizer.php.

Se escribe automáticamente privkey.pem

Especificar publickeyinput privkeyoutput secreto

secreto es el archivo a desencriptar en base64

*Nota

La factorización puede realizarse en el propio ordenador

- para Linux se puede usar cado-nfs, instrucciones aquí https://mersenneforum.org/showthread.php?t=23089
- para Windows tenemos ggnfs y msieve https://download.mersenne.ca/GGNFS y https://download.mersenne.ca/msieve

En ambos casos factoriza números de 60 dígitos en segundos con un hardware decente. 
"""

import requests, BeautifulSoup
from sympy import mod_inverse
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import pyasn1.codec.der.encoder
import pyasn1.type.univ
import base64
import sys

def pempriv(n, e, d, p, q, dP, dQ, qInv):
    template = '-----BEGIN RSA PRIVATE KEY-----\n{}-----END RSA PRIVATE KEY-----\n'
    seq = pyasn1.type.univ.Sequence()
    for i,x in enumerate((0, n, e, d, p, q, dP, dQ, qInv)):
        seq.setComponentByPosition(i, pyasn1.type.univ.Integer(x))
    der = pyasn1.codec.der.encoder.encode(seq)
    return template.format(base64.encodestring(der).decode('ascii'))
     
def main():
    
    print("rsa.py pubkeypeminput privkeypemoutput secreto\n");
       
    finput = sys.argv[1]
    foutput= sys.argv[2]
    secreto= open(sys.argv[3]).read() 
    
    print("input  public key file: " + finput)
    print("output priv key file:   " + foutput)
    print("secreto a desencriptar: " + secreto+"\n")
    
    # primero lee y decodifica el publickey.pem
        
    print("Lectura de la public key...")
    
    pem = open(finput).read()
    pubkey = RSA.importKey(pem)
  
    e       = pubkey.e
    modulus = pubkey.n    
    
    print("modulus es "+str(modulus))
    print("exponente es "+str(e))
    
    # segundo encuentra los primos para el modulus
    
    print("Factorización en primos del modulus...https://www.numberempire.com/numberfactorizer.php")
    
    url = 'https://www.numberempire.com/numberfactorizer.php'
    data= 'number='+str(modulus)+'&_p1=2234'

    headers = { "Content-type": "application/x-www-form-urlencoded",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
		"User-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36",
		"Content-length": str(len(data)),
		"Cookie": "__cfduid=dec1af5f6b07f86963a007474c5e8f1a41598944571; _cp=%7B%22p%22%3Atrue%2C%22s%22%3Atrue%2C%22m%22%3Atrue%7D",
		"Referer": "https://www.numberempire.com/numberfactorizer.php",
		"accept-encoding": ""		}
   
    r = requests.post(url,data=data,headers=headers)    
    r = BeautifulSoup.BeautifulSoup(r.text)
    
    primes = r.find('span', id={'result1'}).text
    
    p = int(primes.split('*')[0])
    q = int(primes.split('*')[1])	 
    
    print("Los primos son "+str(p)+" "+str(q))
    
    # tercero calculando el resto de valores
    
    print("Calculando d,exp1,exp2,coeff...")
    
    phi = (p - 1) * (q - 1)   
    d   = mod_inverse(e, phi)
    
    print("d:  " + str(d));
           
    exp1 = d % (p-1)
    exp2 = d % (q-1)
    coeff = mod_inverse(q, p)
    
    print("exp1: " +str(exp1));
    print("exp2: " +str(exp2));
    print("coeff:  " + str(coeff) +"\n");
    
    print("Ahora el texto del archivo defasn1\n");
    
    # cuarto generate def.asn1

    defasn1 = "asn1=SEQUENCE:private_key\n[private_key]\nversion=INTEGER:0\n\n"
    defasn1+= "n=INTEGER:"+hex(modulus)[:-1]+"\n"
    defasn1+= "e=INTEGER:"+hex(e)[:-1]+"\n"
    defasn1+= "d=INTEGER:"+hex(d)[:-1]+"\n"
    defasn1+= "p=INTEGER:"+hex(p)[:-1]+"\n"
    defasn1+= "q=INTEGER:"+hex(q)[:-1]+"\n"
    defasn1+= "exp1=INTEGER:"+hex(exp1)[:-1]+"\n"
    defasn1+= "exp2=INTEGER:"+hex(exp2)[:-1]+"\n"
    defasn1+= "coeff=INTEGER:"+hex(coeff)[:-1]+"\n"

    print(defasn1);

    filedefasn1 = open(r"def.asn1","w+") 
    filedefasn1.write(defasn1)
    filedefasn1.close() 
        
    print("Secuencia escrita en def.asn1\n");
    
    print("Ahora puedes ejecutar");
    print("1- openssl asn1parse -genconf def.asn1 -out privkey.der -noout");
    print("2- openssl rsa -inform DER -outform PEM -in privkey.der -out privkey.pem");

    # quinto genera directamente privkey
        
    print("\n o generar privkey.pem directamente con python\n");
    
    privkeypem = pempriv(modulus, e, d, p, q, exp1, exp2, coeff);
    
    print(privkeypem)
    
    filepriv = open(foutput,"w+") 
    filepriv.write(privkeypem)
    filepriv.close()     
    
    print(foutput+" generado");

    # sexto desencripta directamente
        
    print("\nTambién se puede usar directamente python para desencriptar la cadena\n\n")
    
    rsa_key = RSA.importKey(privkeypem)
    cipher  = PKCS1_v1_5.new(rsa_key)
    
    secreto = base64.decodestring(secreto)
    phn     = cipher.decrypt(secreto, "Error while decrypting")
    print(phn)
    
if __name__ == "__main__":
    main()
     
     

