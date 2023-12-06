# 3des.py

from des import DES

class TripleDES:
    def __init__(self):
        self.des = DES()

    def generate_key(self):
        return self.des.generate_key()
    
    def binary_to_text(self, binary_data):
        text = ''.join(chr(int(binary_data[i:i+8], 2)) for i in range(0, len(binary_data), 8))
        return text.strip()

    def triple_des_encrypt(self, text, key1, key2, key3=None):
        # If only two keys are provided, use key1 for the first and third stages
        if key3 is None:
            key3 = key1

        # Convert text to binary format
        binary_text = self.des.text_to_binary(text)

        # First encryption
        encrypted = self.des.des_encrypt(binary_text, key1)
        # Decrypt using second key
        decrypted = self.des.des_decrypt(encrypted, key2)
        # Encrypt again using third key
        final_encrypted = self.des.des_encrypt(decrypted, key3)

        return final_encrypted

    def triple_des_decrypt(self, encrypted_text, key1, key2, key3=None):
        if key3 is None:
            key3 = key1

        # Reverse the process: First decrypt with key3
        decrypted = self.des.des_decrypt(encrypted_text, key3)
        # Encrypt with key2
        encrypted = self.des.des_encrypt(decrypted, key2)
        # Final decryption with key1
        final_decrypted = self.des.des_decrypt(encrypted, key1)

        return self.binary_to_text(final_decrypted)

# Usage example
if __name__ == '__main__':
    tdes = TripleDES()
    key1 = tdes.generate_key()
    key2 = tdes.generate_key()
    text = "YourTextHere"

    encrypted_data = tdes.triple_des_encrypt(text, key1, key2)
    print("Encrypted data:", encrypted_data)

    decrypted_data = tdes.triple_des_decrypt(encrypted_data, key1, key2)
    print("Decrypted data:", decrypted_data)
