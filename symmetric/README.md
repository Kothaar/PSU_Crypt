#PSU-CRYPT

PSU-CRYPT is a toy cryptographic project for CS485 as such it doesn't provide
any real security.  

PSU-CRYPT is based on a symmetric feistel cipher implimented in python3 and 
tested on linux. The script expects the plaintext  file to already be in hexcode 
with a single leading 0x on the front end.

## USEAGE

PSU-CRYPT.py expects 3 arguments: <-d/-e> <target file> <key>
Modes:
* -e for encryption
* -d for decryption
* target file is the file which will be encrypted/decrypted
* key is the file containing the key in hex with a leading 0x

Example: 
```
python3 PSU-CRYPT.py -d ciphertext.txt key.txt
```
