import socket
from Crypto.Cipher import AES
from base64 import b64encode
from base64 import b64decode
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.Padding import pad
import rsa
from Crypto.Cipher import PKCS1_OAEP
import time

'''
Author: Trenton Jones
Purpose of : The purpose of this code is to simulate a Secure client-server 
connection using both symmetric and asymmetric encryption.

'''
# Separated the decryption processes for simplicity
def decrypt_message_ecb(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext_bytes = b64decode(ciphertext)
    decrypted_bytes = cipher.decrypt(ciphertext_bytes)
    plaintext = unpad(decrypted_bytes, AES.block_size)
    plaintext = plaintext.decode('utf-8')
    return plaintext

def decrypt_message_cbc(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_bytes = cipher.decrypt(ciphertext)
    plaintext = unpad(decrypted_bytes, AES.block_size)
    plaintext = plaintext.decode('utf-8')
    return plaintext

def main():
    HOST = 'localhost'
    PORT = 12345
    #Creating the key pair in the server
    public_key, private_key = rsa.newkeys(1024)
    #writing them to files as binary
    with open("public.pem","wb") as f:
        f.write(public_key.save_pkcs1("PEM"))
    with open("private.pem","wb") as f:
        f.write(private_key.save_pkcs1("PEM"))

    with open("public.pem", "rb") as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())
    with open("private.pem", "rb") as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())
    with open("public.pem", "rb") as f:
        public_key_bytes = f.read()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        
        while True:

            print("Waiting for connection.....")
            conn, addr = s.accept()
            with conn:
                print("\nThis is the public key!")
                print(public_key)
                print("\nSending public key......")
                conn.send(public_key_bytes)
                print("Public key sent!")
                print('Connected by', addr)
                key = conn.recv(1024)
                key = rsa.decrypt(key,private_key)
                print("Received Key:", key.hex())

                mode = conn.recv(1024)
                mode = rsa.decrypt(mode,private_key)
                mode=mode.decode('utf-8').strip()
                print("Recieving mode in 5 seconds")
                time.sleep(5)
                print("Recieved mode: ", mode)
                print("Waiting on message from client.....")
                numMsg = 0
                if mode == "CBC":
                    iv = conn.recv(AES.block_size)

                    #This was just for troubleshooting purposes on sending and recieving the IV
                    #print("Recieved IV: ", iv.hex())

                    while True:
                        numMsg = numMsg + 1
                        #iv = conn.recv(AES.block_size)
                        ciphertext = conn.recv(1024)
                        if not ciphertext:
                            print("Recieved 'Bye'.")
                            print("Terminating connection.......\n")
                            break
                    
                        decrypted_message = decrypt_message_cbc(ciphertext, key,iv)
                        print("Decrypted Message:", decrypted_message)

                        #Sending a response message
                        replyMsg = input("Enter your reply message: ")
                        with open("privateConvo", "w") as f:
                            f.write(replyMsg)
                        signature = rsa.sign(replyMsg.encode("utf-8"), private_key, "SHA-256")
                        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                        message_bytes = replyMsg.encode('utf-8')
                        padded_message = pad(message_bytes, AES.block_size)
                        ct_bytes = cipher.encrypt(padded_message)
                        ciphertext = ct_bytes
                        print("Sending ciphertext.....")
                        conn.send(ciphertext)
                        time.sleep(2)
                        print("Sent!")
                        print(f"Sending signature for message {numMsg}.....")
                        print(f"Signature for message {numMsg}:\n",signature.hex())
                        conn.send(signature)
                        print("Sent!")
                        print("Waiting on message from client......")

                if mode == "ECB":
                    while True:
                        numMsg = numMsg + 1
                        ciphertext = conn.recv(1024)
                        if not ciphertext:
                            print("Recieved 'Bye'.")
                            print("Terminating connection.......\n")
                            break
                    
                        decrypted_message = decrypt_message_ecb(ciphertext, key)
                        print("Decrypted Message:", decrypted_message)

                        #Sending a response message
                        replyMsg = input("Enter your reply message ")
                        signature = rsa.sign(replyMsg.encode("utf-8"), private_key, "SHA-256")
                        cipher = AES.new(key, AES.MODE_ECB)
                        message_bytes = replyMsg.encode('utf-8')
                        padded_message = pad(message_bytes,AES.block_size)
                        ciphertext = cipher.encrypt(padded_message)
                        ciphertext = b64encode(ciphertext)
                        print("Sending ciphertext.....")
                        conn.send(ciphertext)
                        time.sleep(2)
                        print("Sent!")
                        print(f"Sending signature for message {numMsg}.....")
                        print(f"Signature for message {numMsg}:\n",signature.hex())
                        
                        conn.send(signature)
                        print("Sent!")
                        print("Waiting on message from client......")


if __name__ == "__main__":
    main()
