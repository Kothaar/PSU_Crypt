#!/usr/bin/env python3

import random
import secrets
import sys


def keygen():
    print('keygen')
    print('Input a random number to seed the RNG')
    seed = input()

    p = genPrime()
    # g aka e1
    g = 2
    # d is random number between 1 < d < p
    random.seed(seed)
    d = random.randint(2, p - 2)

    e2 = pow(g, d, p)
    print('Pubkey:', p, g, e2)
    print('Pubkey:', p, g, d)

    writeKey('pubkey.txt', p, g, e2)
    writeKey('prikey.txt', p, g, d)

# random prime number needs to be at least 32 bits
# if p is 33 bits m block size is 32


def genPrime():
    print('genPrime')
    prime = False
    five = 0
    # select a random (k-1)-bit prime q, so that q mod 12 = 5
    while(prime == False):
        while(five != 5):
            q = secrets.randbits(33)
            five = q % 12
        # find n-1 2^k * m

        p = 2 * q + 1

        prime = RabinMiller(p, 40)
        five = 0

    print(p)
    return p


def RabinMiller(n, k):
    # source: https://gist.github.com/Ayrx/5884790

    # if Number ise even it's a composite number

    if n == 2:
        return True

    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n-1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n-1:
                break
        else:
            return False
    return True


def writeKey(file, p, g, eORd):
    print(f'Writing {file}')
    f = open(file, 'w')
    output = f"{p} {g} {eORd}"
    f.write(output)
    f.close()


def charToHex(x):
    return hex(ord(x))[2:].zfill(2)


def encryption():
    print("encryption")
    f = open('ptext.txt', 'r')
    finput = list(f.read())
    f.close()
    hexArray = list(map(charToHex, finput))
    hexString = ''.join(hexArray)
    # each M needs to be 32 bits
    # 8 bits per char. so 4 chars per 32 bits
    # 1 hex number is 8 bits. each hex number is 2 digits so 8 digits
    digits = 8
    # Break up the string into blocks of 32 bits
    m = [hexString[i:i+digits] for i in range(0, len(hexString), digits)]
    # padding
    if len(m[-1]) < digits:
        m[-1] = m[-1].ljust(digits, '0')
    try:
        fpub = open('pubkey.txt', 'r')
    except:
        print('ERROR: Generate keys first using the -g flag first')
        exit(1)
    p, g, e = fpub.read().split()
    fpub.close()
    p = int(p)
    g = int(g)
    e = int(e)

    ctext = open('ctext.txt', 'w+')
    for i in m:
        k = random.randint(2, p-1)
        # print('charset', i)
        c1 = pow(g, k, p)
        c2 = c2mod(e, k, i, p)
        print('m:', i, 'c1:', c1, ' c2:', c2)
        ctext.write(str(c1) + ' ' + str(c2) + '\n')

    ctext.close()

    # m is a list of 32 bit messages with the last one padded with 0's if less then 32 bits

    # block file into 32 bits
    # encrypt m = c1 and c2
    # write c1 and c2 into file


def c2mod(e, k, m, p):

    a = pow(e, k, p)
    b = int(m, 16) % p
    c = (a * b) % p
    c2 = (a * int(m, 16) % p)
    if c != c2:
        print('error mod not working correclty')
    return c2


def decryption():
    try:
        fpri = open('prikey.txt', 'r')
    except:
        print('ERROR: Missing Private Key - run keygen first')
        exit(1)
    p, g, d = fpri.read().split()
    fpri.close()
    p = int(p)
    g = int(g)
    d = int(d)
    print("decryption")
    try:
        fctext = open('ctext.txt', 'r')
    except:
        print('ERROR: Missing encrypted file, run encryption first ')
        exit(1)
    lines = fctext.readlines()
    fctext.close()
    fdtext = open('dtext.txt', 'w+')
    string = ''
    for line in lines:
        c1, c2 = line.split()
        c1 = int(c1)
        c2 = int(c2)
        m = c1c2Mod(c1, c2, p, d)
        hexM = hex(m)[2:]
        stripped = hexM
        stripped = hexM.rstrip('0')
        # Special casing for too many zeros stripped
        if len(stripped) % 2 != 0 and stripped[:1] != 'a':
            stripped = stripped + '0'
        # Special casing for \n new lines in hex. Its represented by 0a so often it gets changed to a. This fixes it so it will read as 0a again.
        if len(stripped) % 2 == 1:
            stripped = '0' + stripped
        string += bytearray.fromhex(stripped).decode('ascii', 'ignore')

    print(string)
    fdtext.write(string)
    fdtext.close()


def c1c2Mod(c1, c2, p, d):
    c1mod = pow(c1, p - 1 - d, p)
    c2mod = c2 % p
    m = (c1mod * c2mod) % p
    return m


def usage():
    print('Enter: \ng for keygen \ne for encryption \nd for decryption \nf to run all 3 ')
    return input()



def main():
    try:
        userinput = sys.argv[1]
    except:
        userinput = '-' + usage()

    if userinput == '-g':
        keygen()
    elif userinput == '-e':
        encryption()
    elif userinput == '-d':
        decryption()
    elif userinput == '-f':
        keygen()
        encryption()
        decryption()
    else:
        print('Bad Input!')

    exit(0)


if __name__ == "__main__":
    main()
