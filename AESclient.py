import sys
import socket
import time
import base64
import rsa
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from base64 import b64encode
from base64 import b64decode


def generate_iv():
    return get_random_bytes(AES.block_size)
def generate_aes_key(keysize):
    if keysize not in [128, 192, 256]:
        print("Invalid key size. Key size must be 128, 192, or 256 bits.")
        sys.exit(1)
    return get_random_bytes(keysize // 8)


# Separated the decryption processes for simplicity
def decrypt_message_ecb(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext_bytes = b64decode(ciphertext)
    decrypted_bytes = cipher.decrypt(ciphertext_bytes)
    plaintext = unpad(decrypted_bytes, AES.block_size)
    plaintext = plaintext.decode('utf-8')
    return plaintext

#IV will be generated in the main method
def decrypt_message_cbc(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_bytes = cipher.decrypt(ciphertext)
    plaintext = unpad(decrypted_bytes, AES.block_size)
    plaintext = plaintext.decode('utf-8')
    return plaintext

def main():
    #checks if program call is too long or too short
    if len(sys.argv) != 3:
        print("Usage: python client.py <keysize> <mode>")
        sys.exit(1)
    
    
    keysize = int(sys.argv[1])
    mode = sys.argv[2]
    if mode.upper() != "CBC" and mode.upper() != "ECB":
        print("Invalid mode. Mode must be ECB or CBC.")
        sys.exit(1)

    
    #Generates the keysize and validates
    key = generate_aes_key(keysize)
    

    #Prints the key in hex for readability
    print("AES Key:", key.hex())
    
    HOST = 'localhost'
    PORT = 12345
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("Receiving public key.....")
        # Receiving public key
        public_key_bytes = s.recv(1024)
        public_key = rsa.PublicKey.load_pkcs1(public_key_bytes)
        print("Received public key:", public_key)
        #Sending key
        encrypted_key = rsa.encrypt(key,public_key)
        s.sendall(encrypted_key) 
        print(f"Sending mode: {mode.upper()}, in 5 seconds.....")
        #Sleeps to make sure mode is sent properly
        time.sleep(5)
        mode_bytes = mode.upper().encode('utf-8')
        mode_bytes_enc = rsa.encrypt(mode_bytes,public_key)
        print(f"Mode: {mode.upper()}, sent!")
        s.sendall(mode_bytes_enc)

        #different processes are followed depending on the mode entered on the command prompt
        if mode.upper() == "CBC":
            iv = generate_iv()

            #This was just for troubleshooting purposes on sending and recieving the IV
            #print("The IV is: ", iv.hex())
            
            s.send(iv)
            while True:
                user_input = input("Enter your message (type 'bye' to exit): ")
                #Disconnects from server if bye is sent
                if user_input.lower() == 'bye':
                    print("Sending 'bye'.")
                    print("Goodbye!")
                    break
                cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                message_bytes = user_input.encode('utf-8')
                padded_message = pad(message_bytes, AES.block_size)
                ct_bytes = cipher.encrypt(padded_message)
                ciphertext = ct_bytes
                s.send(ciphertext)
                # Waits for server reply
                print("Waiting on a response......")
                time.sleep(5)
                responeCT = s.recv(1024)
                decryptedResponse = decrypt_message_cbc(responeCT,key,iv)
                print("Decrypted Message:", decryptedResponse)
                time.sleep(2)
                print("Receiving signature.....")
                signature = s.recv(1024)
                rsa.verify(decryptedResponse.encode("utf-8"),signature,public_key)
                print("message verified!")
                print(rsa.verify(decryptedResponse.encode("utf-8"),signature,public_key))
            
        elif mode.upper() == "ECB":
            while True:
                user_input = input("Enter your message (type 'bye' to exit): ")
                if user_input.lower() == 'bye':
                    print("Sending 'bye'.")
                    print("Goodbye!")
                    break
                #user_bytes = user_input.encode()
                cipher = AES.new(key, AES.MODE_ECB)
                message_bytes = user_input.encode('utf-8')
                #Pads the ciphertext to meet AES standards
                padded_message = pad(message_bytes,AES.block_size)
                ciphertext = cipher.encrypt(padded_message)
                ciphertext = b64encode(ciphertext)
                
                s.send(ciphertext)
                #Waits for server response
                print("Waiting on a response......")
                time.sleep(5)
                responeCT = s.recv(1024)
                decryptedResponse = decrypt_message_ecb(responeCT,key)
                print("Decrypted Message:", decryptedResponse)
                time.sleep(2)
                print("Receiving signature.....")
                signature = s.recv(1024)
                rsa.verify(decryptedResponse.encode("utf-8"),signature,public_key)
                print("message verified!")


if __name__ == "__main__":
    main()
