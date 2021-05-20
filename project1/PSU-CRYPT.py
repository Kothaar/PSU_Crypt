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
    

def read_hex_file(file):
    f = open(file, 'r')
    # removes 0x from front and \n from end
    # Assumes file is already in hex with only one leading 0x in the file
    input = f.read()

    input = input[2:]

    #if input[:2] == '0x':
        #input = input[2:]

    #else:
       # f.close()
        #input = convert_to_hex(file)

    # Trims off newline at end of file
    # Replaced later
    endline = [input]
    endline = endline[0]
    endline = endline[-1:]
    if endline == '\n':
        input = [input[:-1]][0]
        
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
    k0 = key[0:4]
    k1 = key[4:8]
    k2 = key[8:12]
    k3 = key[12:16]
    R = [int(w0,16) ^ int(k0,16), int(w1, 16) ^ int(k1, 16), int(w2, 16) ^
            int(k2, 16), int(w3,16) ^ int(k3,16)]
    return R

def use_case():
    print("BAD INPUT!\nExpecting: python3 PSU-CRYPT <encrypt/decrypt> <plaintext/cyphertext> <key>")
    return -1

def F(r0, r1, subkey_array):
    global ROUND
    # TODO Clean this up
    # Pull out subkeys to be passed around
    # subkeys are dec value ie 255 
    # The values of r0/r1 are hex in int form
    subkey1 = int(subkey_array[ROUND][0], 16)
    subkey2 = int(subkey_array[ROUND][1], 16)
    subkey3 = int(subkey_array[ROUND][2], 16)
    subkey4 = int(subkey_array[ROUND][3], 16)
    subkey5 = int(subkey_array[ROUND][4], 16)
    subkey6 = int(subkey_array[ROUND][5], 16)
    subkey7 = int(subkey_array[ROUND][6], 16)
    subkey8 = int(subkey_array[ROUND][7], 16)
    sub_subkey_array_1 = [subkey1, subkey2, subkey3, subkey4]
    sub_subkey_array_2 = [subkey5, subkey6, subkey7, subkey8]
    subkey9 = subkey_array[ROUND][8]
    subkey10 = subkey_array[ROUND][9]
    subkey11 = subkey_array[ROUND][10]
    subkey12 = subkey_array[ROUND][11]
    mod = 2 ** 16
    cat1 = int(str(subkey9).zfill(2) + str(subkey10).zfill(2), 16)
    cat2 = int(str(subkey11).zfill(2) + str(subkey12).zfill(2), 16)


    t0 = int(G(r0, sub_subkey_array_1), 16)
    t1 = int(G(r1, sub_subkey_array_2), 16)
    f0 = ((t0 + 2 * t1 + cat1) % mod)
    f1 = ((2* t0 + t1 + cat2) % mod)
    print("t0:", hex(t0), "t1:", hex(t1))
    print("f0:", hex(f0), "f1:", hex(f1))
    return [f0, f1]


def G(w, sub_subkey_array):
    w = hex(w)[2:].zfill(4)

    g1 = int(w[0:2], 16)
    g2 = int(w[2:4], 16)
    g3 = Ftable(g2 ^ sub_subkey_array[0]) ^ g1
    g4 = Ftable(g3 ^ sub_subkey_array[1]) ^ g2
    g5 = Ftable(g4 ^ sub_subkey_array[2]) ^ g3
    g6 = Ftable(g5 ^ sub_subkey_array[3]) ^ g4
    print("g1:", hex(g1), "g2:",hex(g2),"g3:", hex(g3),"g4:", hex(g4),"g5:", hex(g5),"g6:", hex(g6))

    return hex(g5).zfill(2) + hex(g6)[2:].zfill(2)

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
    if pad == 16 or pad == 0:
        return string


    pad = 16 - pad

    # add required # of 0's + number of 0's added to end
    string = string.ljust(pad - len(str(pad)) + len(string), '0') + str(pad)

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
    file = read_hex_file(file)
    file = pad_string(file)

    key = sys.argv[3]
    key = read_hex_file(key)

    print(file, [file])

    mode(file, key, decrypt)



if __name__ == "__main__":
    main()


