# credits: https://github.com/TheCrowned/padding-oracle-attack
# I just improved the readability of the code and fixed the correctness testing part

from Crypto.Cipher import AES
from Crypto import Random
import lorem

randgen = Random.new()
key = randgen.read(16) # AES128 key len

def _add_padding(msg):
    pad_len = AES.block_size - (len(msg) % AES.block_size)
    padding = bytes([pad_len]) * pad_len
    return msg + padding

def _remove_padding(data):
    pad_len = data[-1]    
    if pad_len < 1 or pad_len > AES.block_size:
        return None
    for i in range(1, pad_len):
        if data[-i-1] != pad_len:
            return None
    return data[:-pad_len]

def encrypt(msg):
    iv = randgen.read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(_add_padding(msg))  # NB: iv is added as an extra block at the top!

def _decrypt(data):
    iv = data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return _remove_padding(cipher.decrypt(data[AES.block_size:]))

def is_padding_ok(data):
    return _decrypt(data) is not None





def attack( ciphertext ):
    blocks = [ciphertext[i:i+AES.block_size] for i in range(0, len(ciphertext), AES.block_size)]
    plaintext = bytes()

    # build pair of blocks starting from end of message
    for block_n in range( len(blocks)-1, 0, -1 ):
        X = b'\0'*AES.block_size # output of block cipher decoding values
        P = b'\0'*AES.block_size

        # scroll the bytes starting from the last of the block
        for byte in range( AES.block_size-1, -1, -1 ): # 15,14,13....0
            curr_padding_len = AES.block_size - byte

            # the bytes we previously extracted must follow the same padding as the current position
            # (secondo round - last byte)       HC1[15] = 02 ^ X[15] -> DECRYPT -> HC1[15] ^ X[15] = 02
            #
            # (third round - last two byte)     HC1[15] = 03 ^ X[15] -> DECRYPT -> HC1[15] ^ X[15] = 03
            #                                   HC1[14] = 03 ^ X[14] -> DECRYPT -> HC1[14] ^ X[14] = 03
            hacked_ciphertext_tail = b''.join([(curr_padding_len^b).to_bytes() for b in X[byte+1:]])

            # trying every byte possible values
            for i in range(256):
                
                HC1 = blocks[block_n-1][:byte] \
                    + (i^blocks[block_n-1][byte]).to_bytes() \
                    + hacked_ciphertext_tail \
                    + blocks[block_n]

                if is_padding_ok(HC1): # we guessed a possible padding byte ヽ(^o^)ノ
                    
                    if byte > 0: # otherwise the previous byte does not exist
                        
                        # test the correctness by editing the previous byte
                        # why it works? the padded bytes must be ended if no errors occurs because they have all the same value
                        X_test = HC1[:byte-1] \
                                 + (1^HC1[byte-1]).to_bytes() \
                                 + HC1[byte:]
                        if( not is_padding_ok( X_test ) ):
                            continue

                    # we can extract the value of X
                    # X       = HC1       ^ P manipulated
                    # X[byte] = HC1[byte] ^ P[byte] manipulated
                    # X[byte] = XY        ^ 01                       > (first round) cause valid padding
                    X = X[:byte] \
                      + (HC1[byte]^curr_padding_len).to_bytes() \
                      + X[byte+1:]

                    # we can extract the value of the plaintext
                    # P[byte] = C1[byte] ^ X[byte]
                    P = P[:byte] \
                      + (blocks[block_n-1][byte]^X[byte]).to_bytes() \
                      + P[byte+1:]
                    
                    break

        plaintext = P + plaintext

    return _remove_padding(plaintext)


if __name__ == '__main__':
    msg = lorem.paragraph().encode('utf8')
    cracked_ct = attack(encrypt(msg))
    assert len(cracked_ct) == len(msg) and cracked_ct == msg, \
        f"\n\033[91mlen(cracked ciphertext)={len(cracked_ct)} != len(plaintext)={len(msg)}\n\n{cracked_ct}\n!=\n{msg}"
    print(f"\033[94mRandom message:\n\033[92m{msg.decode('utf8')}\n\n")
    print(f"\033[94mCracked ciphertext:\n\033[92m{cracked_ct.decode('utf8')}\n")
