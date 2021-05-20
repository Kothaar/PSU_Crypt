#! /bin/python3
import sys
import binascii

G_KEY = ""
ROUND = 0
F_TABLE = []
HEX_FILE = False

def concate_hex(w,x,y,z):
    return hex(w).zfill(4)[2:].zfill(4) + hex(x)[2:].zfill(4) + hex(y)[2:].zfill(4) + hex(z)[2:].zfill(4)

def mode(input, key, decrypt):
    global ROUND
    subkey_array = gen_subkeys(key)

    if decrypt == True:
        subkey_array = subkey_array[::-1]

    output = ''

#============================================================
    for i in range(int(len(input)/16)):
        R = whitening(input[i*16:i*16+16], key)

        print(R, R[0], len(R[0]) ,"bytes")

        r0 = R[0]
        r1 = R[1]
        r2 = R[2]
        r3 = R[3]

        while ROUND < 16:
            print("Beginning of Round: ", ROUND)
            tr0 = r0
            tr1 = r1
            f = F(r0, r1,subkey_array)
            r0 = r2 ^ f[0]
            r1 = r3 ^ f[1]
            r2 = tr0
            r3 = tr1 
            print("End of Round: ", ROUND)
            print('\n')
            ROUND += 1

        y0 = r2
        y1 = r3
        y2 = r0
        y3 = r1
        ROUND = 0
        block = hex(y0)[2:]+ hex(y1)[2:]+ hex(y2)[2:] + hex(y3)[2:]
        block = whitening(block ,key)
        block = concate_hex(block[0], block[1], block[2], block[3])
        output = output + block
#============================================================

    
    if decrypt == True:
        output = '0x' + output
        output = output + "\n"
        f = open('plaintext.txt', 'w+')
        f.write(output)
        print("Output written to plaintext.txt")
    else:
        output = '0x' + output
        output = output + "\n"
        f = open('ciphertext.txt', 'w+')
        f.write(output)
        print("Output written to ciphertext.txt")

    print('OUTPUT: ', output)
    return output
    

def gen_subkeys(key):
    print("SubKeys Generating")
    global G_KEY

    G_KEY = key
    rounds = 16
    four = 4
    subkeys = 12
    key_array = []
    key_array = [[K(((4*j)+(i%4))) for i in range(subkeys)] for j in range(rounds)]

    return key_array

def K(x): 
    global G_KEY
    # lots of string transformations to handle the left shift
    bit_string = bin(int(G_KEY, 16))
    bit_string = bit_string[2:]
    # leadings 0's are automatcially ignored by python, readding them back
    bit_string = bit_string.zfill(64)

    # Grab left most bit; place it on end
    l_shift_bit = bit_string[:1]
    bit_string = bit_string[1:]+l_shift_bit

    # Convert G_KEY back to hex form without leading 0x
    G_KEY = hex(int(bit_string,2))[2:]
    
    # inversing they key causes puts the key in the correct position, but
    # creates backwards subkeys, so they also need to be inverted back
    G_KEY = G_KEY[::-1]
    sub_key = [G_KEY[i:i+2][::-1] for i in range(0,len(G_KEY),2)]
    G_KEY = G_KEY[::-1]

    # the picked subkey
    key_num = x % 8
    return sub_key[key_num]
    

def read_file(file):
    f = open(file, 'rb')
    # removes 0x from front and \n from end
    # Assumes file is already in hex with only one leading 0x in the file
    input = f.read()

    return input
    
# Expects 64 bit block of texts devides into 4 words
# XOR each word with 16 bits of the key
def whitening(bit_block, key):
    print("whitening")
    # splice the string into the 4 words
    w0 = bit_block[0:4]
    w1 = bit_block[4:8]
    w2 = bit_block[8:12]
    w3 = bit_block[12:16]
    # splice the key string into the 4 words
    k0 = key[2:6]
    k1 = key[6:10]
    k2 = key[10:14]
    k3 = key[14:18]
    
    r0 = bytes([a ^ b for a, b in zip(w0,k0)])
    r1 = bytes([a ^ b for a, b in zip(w1,k1)])
    r2 = bytes([a ^ b for a, b in zip(w2,k2)])
    r3 = bytes([a ^ b for a, b in zip(w3,k3)])

    R = [r0, r1, r2, r3 ]
    return R

def use_case():
    print("BAD INPUT!\nExpecting: python3 PSU-CRYPT <encrypt/decrypt> <plaintext/cyphertext> <key>")
    return -1

def F(r0, r1, sa):
    global ROUND

    mod = 2 **16
    sk0 = sa[ROUND][0]
    sk1 = sa[ROUND][1]
    sk2 = sa[ROUND][2]
    sk3 = sa[ROUND][3]
    sk4 = sa[ROUND][4]
    sk5 = sa[ROUND][5]
    sk6 = sa[ROUND][6]
    sk7 = sa[ROUND][7]
    sk8 = sa[ROUND][8]
    sk9 = sa[ROUND][9]
    sk10 = sa[ROUND][10]
    sk11 = sa[ROUND][11]

    ssa1 = [sk0, sk1, sk2, sk3]
    ssa2 = [sk4, sk5, sk6, sk7]

    cat1 = 0
    cat2 = 0

    t0 = G(r0,ssa1)
    t1 = G(r1,ssa2)

    f0 = (t0 + 2*t1 + cat1) % mod
    f1 = (t1 + 2*t0 + cat2) % mod

    


    return 0

def G(w, ssa):

    print("G FUNCTION", w, ssa)
    # w is 4 bytes this is 16 bits
    # g1 is the left 8 bits
    g1 = [hex(w[0]),hex(w[1])]
    g2 = [w[2],w[3]]
    print("SSA" , ssa)
    print("G1",  g1)
    print("G2", g2)





    return 0


def create_Ftable():
    global F_TABLE
    print("GENERATING FTABLE")
    f = open('ftable.txt', 'r')
    lines = [line.rstrip('\n').split(',') for line in f]
    F_TABLE = lines
    return 0


def Ftable(pos):
    global F_TABLE

    # get row/col from pos
    pos = hex(pos)
    if len(pos) < 4:
        row = 0
        col = int(pos[2:3], 16)
    else:
        row = int(pos[2:3], 16)
        col = int(pos[3:4], 16)

    pos = F_TABLE[row][col]
    return int(pos, 16)

    
def pad_string(string):

    # Calc how many 0's need to be added
    pad = len(string) % 16
    pad = 16 - pad
    string = string + bytes(pad)

    return string

def main():
    input = sys.argv[1]

    if input == '-d':
        print("Running Decryption")
        decrypt = True
    elif input == '-e':
        print("Running Encryption")
        decrypt = False
    else:
        return use_case()

    create_Ftable()

    file = sys.argv[2]
    file = read_file(file)
    file = pad_string(file)

    key = sys.argv[3]
    key = read_file(key)

    mode(file, key, decrypt)



if __name__ == "__main__":
    main()


