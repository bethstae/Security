from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import pickle

class Principal:

    # key_length: RSA key length this principal will use
    # name: name of principal, save key under "name".der in DER format
    def __init__(self, key_length, name):
        # YOUR TASK STARTS HERE
        self.key_length = key_length
        self.name = name
        self.own_key = self.create_rsa_key(key_length)
        #print("This is the private key for ",self.name, " :", self.own_key.exportKey())
        #print("This is the public key for ",self.name, " :", self.own_key.publickey().exportKey())
        #print("Is there a difference?", self.own_key.publickey())
        # YOUR TASK ENDS HERE
        with open("{}.der".format(name), "wb") as out_fh:
            out_fh.write(self.own_key.exportKey(format ='DER', pkcs=1))

    # Create RSA key of given key_length: This is the rsa key used for the 
	#public and private key for this instance 
    def create_rsa_key(self, key_length):
        # YOUR TASK STARTS HERE
        rsa_keypair = RSA.generate(self.key_length)
        #print("This is the rsa_keypair for ",self.name, " :", rsa_keypair)
        # YOUR TASK ENDS HERE
        return rsa_keypair

    # Return public key part of public/private key pair
	#Did not add any code to this
    def get_public_key(self):
        # YOUR TASK STARTS HERE
        # ...
        # YOUR TASK ENDS HERE
        public_key = self.own_key.publickey()
        return public_key

    # Receiving means reading an hybrid-encrypted message from a file.
    # Returns: encrypted key (bytes), encrypted message (bytes), IV (bytes),
    # number of padding bytes
    def receive(self, filename):
        # YOUR TASK STARTS HERE
		#Opens a binary file and loads the data into the necessary variables
		#Inspired by https://stackabuse.com/reading-and-writing-lists-to-a-file-in-python/
        with open(filename,"rb") as enc_file:
            msg = pickle.load(enc_file)
            ck_bytes, cm_bytes, iv_bytes, pad_len_int = msg[0], msg[1], msg[2], msg[3]
            #ck_bytes, cm_bytes, iv_bytes, pad_len_int =  [ enc_file.read(x) for x in (256,-i32,-16,-1) ]
        # YOUR TASK ENDS HERE
        return [ck_bytes, cm_bytes, iv_bytes, pad_len_int]

    # Sending means writing an encrypted message plus metadata to a file.
    # Line 1: RSA-encrypted symmetric key, as hex string.
    # Line 2: Symmetrically encrypted message, as hex string.
    # Line 3: IV as hex string
    # Line 4: Number of padding bytes (string of int)
    def send(self, filename, msg):
        # YOUR TASK STARTS HERE
        #with open(filename, "wb") as enc_file:
        with open(filename, "wb") as hexfile:
            pickle.dump(msg, hexfile)
           # [ hexfile.write(x) for x in  (msg[0], msg[1],msg[2], str(msg[3]).encode()) ]
        # YOUR TASK ENDS HERE
        pass

# Hybrid Cipher encapsulates the functionality of a hybrid cipher using
# RSA and AES-CBC.
# Key length of AES is a parameter.
class HybridCipher:

    # length_sym: length of symmetric key. Must be 128, 192, or 256.
    # own_key: public/private key pair of owner (principal who can decrypt)
    # remote_pub_key: public key of principal this hybrid cipher is encrypting to
    def __init__(self, length_sym, own_key, remote_pub_key):
        # YOUR TASK STARTS HERE
        self.length_sym = length_sym
        self.own_key = own_key
        self.remote_pub_key = remote_pub_key
        self.cipher, self.iv, self.sym_key = self.create_aes_cipher(self.length_sym)
        # YOUR TASK ENDS HERE
        pass


    # Creates an AES cipher in CBC mode with random IV, and random key
    # Returns: cipher, IV, symmetric key
	#inspiration from https://www.novixys.com/blog/using-aes-encryption-decryption-python-pycrypto/
    def create_aes_cipher(self, length):
        # YOUR TASK STARTS HERE
        new_length = int(length/8) #makes 256, 192, 128 to 32, 24 and 16 respectively
        sym_key = get_random_bytes(new_length) #random key
        iv = get_random_bytes(AES.block_size)  #random iv
        cipher = AES.new(sym_key, AES.MODE_CBC, iv) #creates cipher key
        #print("This is the sym key", sym_key)
        #print("This is the IV", iv)
        # YOUR TASK ENDS HERE
        return cipher, iv, sym_key


    # Decrypted hybrid-encrypted msg
    # Returns: decrypted message with padding removed, as string
	#inspiration from https://pycryptodome.readthedocs.io/en/latest/src/examples.html#generate-an-rsa-key
    def decrypt(self, msg):
        # YOUR TASK STARTS HERE
		#decrypt the session key using RSA (private key belonging to receiver)
        cipher_rsa = PKCS1_OAEP.new(self.own_key)
        session_key = cipher_rsa.decrypt(msg[0]) 
		#create the aes cipher using the decrypted key and obtained iv
        aes = AES.new(session_key, AES.MODE_CBC, msg[2])
		#decrypt message and then strip the padding
        rcvd_msg_dec = self.strip_pad(aes.decrypt(msg[1]), msg[3])
		#to remove b' '. Inspiration from https://stackoverflow.com/questions/37016946/remove-b-character-do-in-front-of-a-string-literal-in-python-3
        rcvd_msg_dec = rcvd_msg_dec.decode("utf-8") 
        #print("This is the recieved padded message", decd)
        #print("THIS is decd", rcvd_msg_dec)
        # YOUR TASK ENDS HERE
        return rcvd_msg_dec


    # Encrypts plaintext message to encrypt in hybrid fashion.
    # Returns: encrypted symmetric key, encrypted message, IV, number of padding bytes
    def encrypt(self, msg):
        # YOUR TASK STARTS HERE
		#pad the message and then encrypt the message using aes and encrypt aes key using RSA
        cm = self.cipher.encrypt(self.pad(msg))
        cipher = PKCS1_OAEP.new(self.remote_pub_key)
        ck = cipher.encrypt(self.sym_key)
        iv = self.iv
        pad_len = self.amount_to_pad
        #print("This is the encrypted sym key", ck)
        #print("This is the encrypted cm", cm)
        # YOUR TASK ENDS HERE
        return [ck, cm, iv, pad_len]

    # Padding for AES-CBC.
    # Pad up to multiple of block length by adding 0s (as byte)
    # Returns: padded message, number of padding bytes
	#inspiration from https://stackoverflow.com/questions/39653074/aes-cbc-128-192-and-256-encryption-decryption-in-python-3-using-pkcs7-padding
    def pad(self, msg):
        # YOUR TASK STARTS HERE
        padded_msg = msg
        self.amount_to_pad = AES.block_size - (len(msg) % AES.block_size)
        padded_msg += "0"*self.amount_to_pad
	#print(msg_len)
        #print("Amount to pad", self.amount_to_pad)
        #pad = chr(self.amount_to_pad)
        #print("This is the pad", pad)
        #print("Length of padded msg", len(padded_msg)
        # YOUR TASK ENDS HERE
        return padded_msg

    # Strips padding and converts message to str.
    def strip_pad(self, msg, pad_len_int):
        # YOUR TASK STARTS HERE
        #pad = ord(msg[-1])
        msg_unpadded= msg[:-pad_len_int]
        # YOUR TASK ENDS HERE
        return msg_unpadded




def main():
    # We create Alice as a principal. In this example, we choose a
    # 2048 bit RSA key.
    alice = Principal(2048, "alice")
    # We create Bob as a principal.
    bob = Principal(2048, "bob")

    # We create a HybridCipher for Alice to use. She uses Bob's public key
    # because he is the receiver. Her own public/private key pair goes in there, too,
    # for completeness. 
	#chose 128 to be arbitary length
    a_hybrid_cipher = HybridCipher(128, alice.own_key, bob.get_public_key())

    # Alice has a message for Bob.
    msg = "Changed the message for testing purposes and made it longer.Over"
    # Alice uses the hybrid cipher to encrypt to Bob.
    msg_enc = a_hybrid_cipher.encrypt(msg)
    alice.send("msg.enc", msg_enc)

    # Bob receives
    rcv_msg_enc = bob.receive("msg.enc")
    #print("This is the encrypted sym key", rcv_msg_enc[0])
    #print("This is the encrypted message", rcv_msg_enc[1])
    #print("This is iv", rcv_msg_enc[2])
    # Bob creates a HybridCipher. He configures it with his own public/private
    # key pair, and Alice's public key for completeness.
    b_hybrid_cipher = HybridCipher(128, bob.own_key, alice.get_public_key())
    # Bob decrypts.
    dec_msg = b_hybrid_cipher.decrypt(rcv_msg_enc)
    #print(dec_msg)
    #print("This is the original message", msg)
    #print("This is the received message", dec_msg)
    if msg == dec_msg:
        print("This worked!")

main()
