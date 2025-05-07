import rsa

public_key, private_key = rsa.newkeys(1024)

with open("public.pem","wb") as f:
    f.write(public_key.save_pkcs1("PEM"))
with open("private.pem","wb") as f:
    f.write(private_key.save_pkcs1("PEM"))


with open("public.pem", "rb") as f:
    public_key = rsa.PublicKey.load_pkcs1(f.read())
with open("private.pem", "rb") as f:
    private_key = rsa.PrivateKey.load_pkcs1(f.read())

message = "Hello I am Trenton Jones. I am 22"
tag = "This is the encrypted message!\n"
tag = tag.encode()
encrypted_message = rsa.encrypt(message.encode(), public_key)
with open("encrypted.message", "wb") as f:
    f.write(tag)
    f.write(encrypted_message)
    
decrypted_msg = rsa.decrypt(encrypted_message,private_key)
tag = "This is the decrypted message!\n"
tag = tag.encode()
with open("decrypted.message", "wb") as f:
    f.write(tag)
    f.write(decrypted_msg)