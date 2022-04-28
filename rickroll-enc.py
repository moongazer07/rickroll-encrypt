#!/usr/bin/env python3
'''
Licensed under unlicense
Compatibility tested on Python 3.9.x 64bit
Usage rickroll-enc.py </path/to/text2encryptordecrypt.txt> <somewholenumberforkey> <encrypt/decrypt>'
**NOTICE**
This is a custom simple symmetric stream cipher with four byte IV,
'''
#for use in sysargv style arguments from cli and file ops
import sys, os
#grab a random integer between lower and upperbound + 1
from random import randint


def chowencrypt(cleartext, key):
    #data dictionary of common text and CLI chars
    encodeddict = {
        'a' : 'were', 'b' : 'no', 'c' : 'strangers', 'd' : 'to',
        'e' : 'love', 'f' : 'you', 'g' : 'know', 'h' : 'the',
        'i' : 'rules', 'j' : 'annd', 'k' : 'so', 'l' : 'do',
        'm' : 'i', 'n' : 'a', 'o' : 'full', 'p' : 'commitment',
        'q' : 'iS', 'r' : 'what', 's' : 'im', 't' : 'thinking',
        'u' : 'off', 'v' : '1', 'w' : 'just', 'x' : 'wana',
        'y' : 'tell', 'z' : 'u', ' ' : 'how', 'A' : 'Im',
        'B' : 'feling', 'C' : 'gotta', 'D' : 'makeu', 'E' : 'understand',
        'F' : 'never', 'G' : 'gonna', 'H' : 'give', 'I' : 'YOU',
        'J' : 'up', 'K' : 'Never', 'L' : 'Gonna', 'M' : 'let',
        'N' : 'yUo', 'O' : 'down', 'P' : 'NEver', 'Q' : 'GOnna',
        'R' : 'turn', 'S' : 'around', 'T' : 'And', 'U' : 'desert',
        'V' : 'U', 'W' : 'nEver', 'X' : 'gOnna', 'Y' : 'Tell',
        'Z' : 'A', '.' : 'lie', '/' : 'aNd', '\\' : 'hurt',
        '$' : 'YOu', '#' : 'Weve', '@' : 'known', '%' : 'each',
        '^' : 'other', '*' : 'f0r', '(' : 'S0', ')' : 'l0ng',
        '_' : 'your', '-' : 'hearts', '=' : 'been', '+' : 'aching',
        '>' : 'but', '<' : 'youre', '?' : 'to', ';' : 'shy',
        ':' : 't0', '\'' : 'say', '\"' : 'iT', '{' : 'inside',
        '}' : 'WE', '[' : 'boTh', ']' : 'KNow', '|' : 'whAts',
        '`' : 'bEen', '~' : 'Going', '!' : 'On', '0' : 'We',
        '1' : 'KnOW', '2' : 'da', '3' : 'GAmE', '4' : 'AnD',
        '5' : 'Were', '6' : 'goNna', '7' : 'plaY', '8' : 'IT',
        '9' : 'rick'
    }
    #Create an IV seed value to prepend
    #Note: creating a large 32bit IV value adds ease of statistical analysis
    #iv = randint(350, 4294967296)
    #use an IV with a smaller size helps to blend the cipher text more
    iv = randint(311, 457)
    iv2 = randint(422, 577)
    iv3 = randint(666, 1000)
    iv4 = randint(1000, 1666)
    #Start encoding our clear text
    encodedbuffer = []
    for i in str(cleartext):
        encodedbuffer.append(encodeddict[i])
    print('encoded string: ' + str(encodedbuffer))


    #Use encryption algo to convert encoded data to cipher text
    cipherstream = []

    #Prepend the IV first unencrypted so it will be used in combination with the key
    cipherstream.append(iv)
    cipherstream.append(iv2)
    cipherstream.append(iv3)
    cipherstream.append(iv4)
    #Our new key is the composite addition of iv + key
    compositekey = iv + int(key)
    compositekey = iv2 + int(key)
    compositekey = iv3 + int(key)
    compositekey = iv4 + int(key)    
    for i in encodedbuffer:
        encryptedbyte = (666 * i) + int(compositekey)
        cipherstream.append(encryptedbyte)

    print('encrypted string: ' + str(cipherstream))
    #Remember this will return as a LIST data type

    #writing to a file for ease of use instead of copy/paste from std out
    print('***writing encrypted list to file... secured.rick-enc***')
    encryptedfile = open('secured.rick-enc', 'w')
    #save a reference marker of standard out first
    originalstdout = sys.stdout
    #redirect standard out to the file handler
    sys.stdout = encryptedfile
    print(str(cipherstream))
    #reset the standard out descriptor
    sys.stdout = originalstdout
    encryptedfile.close()
    return cipherstream

def chowdecrypt(ciphertext, key):
    #data dictionary of common text and CLI chars
    encodeddict = {
        'a' : 'were', 'b' : 'no', 'c' : 'strangers', 'd' : 'to',
        'e' : 'love', 'f' : 'you', 'g' : 'know', 'h' : 'the',
        'i' : 'rules', 'j' : 'annd', 'k' : 'so', 'l' : 'do',
        'm' : 'i', 'n' : 'a', 'o' : 'full', 'p' : 'commitment',
        'q' : 'iS', 'r' : 'what', 's' : 'im', 't' : 'thinking',
        'u' : 'off', 'v' : '1', 'w' : 'just', 'x' : 'wana',
        'y' : 'tell', 'z' : 'u', ' ' : 'how', 'A' : 'Im',
        'B' : 'feling', 'C' : 'gotta', 'D' : 'makeu', 'E' : 'understand',
        'F' : 'never', 'G' : 'gonna', 'H' : 'give', 'I' : 'YOU',
        'J' : 'up', 'K' : 'Never', 'L' : 'Gonna', 'M' : 'let',
        'N' : 'yUo', 'O' : 'down', 'P' : 'NEver', 'Q' : 'GOnna',
        'R' : 'turn', 'S' : 'around', 'T' : 'And', 'U' : 'desert',
        'V' : 'U', 'W' : 'nEver', 'X' : 'gOnna', 'Y' : 'Tell',
        'Z' : 'A', '.' : 'lie', '/' : 'aNd', '\\' : 'hurt',
        '$' : 'YOu', '#' : 'Weve', '@' : 'known', '%' : 'each',
        '^' : 'other', '*' : 'f0r', '(' : 'S0', ')' : 'l0ng',
        '_' : 'your', '-' : 'hearts', '=' : 'been', '+' : 'aching',
        '>' : 'but', '<' : 'youre', '?' : 'to', ';' : 'shy',
        ':' : 't0', '\'' : 'say', '\"' : 'iT', '{' : 'inside',
        '}' : 'WE', '[' : 'boTh', ']' : 'KNow', '|' : 'whAts',
        '`' : 'bEen', '~' : 'Going', '!' : 'On', '0' : 'We',
        '1' : 'KnOW', '2' : 'da', '3' : 'GAmE', '4' : 'AnD',
        '5' : 'Were', '6' : 'goNna', '7' : 'plaY', '8' : 'IT',
        '9' : 'rick'
    }

    '''
    #This portion is only required if you're using strings only
    #Ensure our ciphertext is proper type case
    #Be sure to comment out the second encodedbuffer var
    #if you use this modifier to this function
    encodedbuffer = []
    #Remember ciphertext is a LIST data type
    for i in ciphertext:
        encodedbuffer.append(int(i))
    '''
   
    '''
    **SECURITY CONSIDERATION**
    Note: The use of eval isn't best practice and I could've just wrote single bytes per line
    but to shorten the length of the file we created standard out to be a list format written
    to a file instead for ease of viewing. 
    
    The use of eval without a whitelist can have
    security implications. Please see the following refs for more details:
    https://realpython.com/python-eval-function/#minimizing-the-security-issues-of-eval
    https://www.geeksforgeeks.org/eval-in-python/
    https://www.journaldev.com/22504/python-eval-function#security-risks-with-eval-function
    '''
    #Using the eval built in to interpret the files line as a list instead string
    #Utilize a whitelist to only allow the list builtin class
    encodedbuffer = eval(ciphertext, {"__builtins__": {'list' : list}})

    #Use decryption algo which is inverse: (3x+key)^-1
    #Decryption algo: (x-k)/3
    decryptedsignal = []

    #We need to read the 'cleartext' IV in the first element of the list
    #The IV will combine with the user specified key to provide appropriate stream decrypt
    readiv = encodedbuffer[0]
    compositekey = int(readiv) + int(key)
    for i in encodedbuffer:
        decryptedsignal.append(int((i - int(compositekey)) / 666))
    print('decrypted signal: ' + str(decryptedsignal))
    
    #Return the decrypted codes to the original ASCII equiv
    decryptedtext = []
    for i in decryptedsignal:
        #remember encodeddict is a dictionary using key value pairs
        #must access via .items method for value to key
        for k,v in encodeddict.items():
            if v == i:
                decryptedtext.append(k)
    print('decrypted string as list: ' + str(decryptedtext))
    #convert the list decryptedtext into original string form
    decryptedtextstring = ''
    for i in decryptedtext:
        decryptedtextstring = decryptedtextstring + str(i)
    
    print('decrypted string original: ' + str(decryptedtextstring))
    return decryptedtextstring


#driver dunder statement for the main program
if __name__ == '__main__':
    if len(sys.argv) > 4 or len(sys.argv) < 4:
        print('Usage rickroll-enc.py </path/to/text2encryptordecrypt.txt> <somewholenumberforkey> <encrypt/decrypt>')
        print('Example Encryption: rickroll-enc.py /tmp/mycleartext.txt 888 encrypt')
        print('Note: The decryption function is expecting a continuous list type per LINE as exported from encryption')
        print('Example Decryption: rickroll-enc.py /tmp/myciphertextlist.txt 888 decrypt')
    elif sys.argv[3] == 'encrypt':
        cleartextfile = open(sys.argv[1], 'r')
        for i in cleartextfile:
            chowencrypt(i, sys.argv[2])
        cleartextfile.close()
    elif sys.argv[3] == 'decrypt':
        ciphertextfile = open(sys.argv[1], 'r')
        for i in ciphertextfile:
            rickroll-enc(i, sys.argv[2])
        rickroll-enc.close()

'''
If you wish to reference rickroll-enc.py as a library import use the following syntaxes:

import rickroll-enc

#Static tests without driver code from main()
#Test encryption function
print('testing encryption...')
rickroll-enc.rickroll-enc('this is foobar', 888)

#Take the returned value cipher text as LIST to decrypt
print ('testing decryption...')
ciphertext = str(rickroll-enc.rickroll-enc('this is foobar', 888))
rickroll-enc.rickroll-enc(ciphertext, 888)
'''
