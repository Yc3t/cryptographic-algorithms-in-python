import random


#basic implementation of DES

class DES:
    #damn tables needed
    #IP table
    IP_TABLE = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]

    #Final IP table (IP^-1)	
    FP_TABLE = [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    ]

    #E table
    EXPANSION_TABLE = [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ]


    #P table
    P_TABLE = [
        16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25,
    ]

    #PC-1 table
    PC1_TABLE = [
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    ]

    #PC-2 table
    PC2_TABLE = [
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    ]


    #Shift schedule
    SHIFT_SCHEDULE = [
        1, 1, 2, 2,
        2, 2, 2, 2,
        1, 2, 2, 2,
        2, 2, 2, 1
    ]

    # The S-Box tables
    S_BOXES = [
        # S1
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
        # S2
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
        # S3
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
        # S4
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
        # S5
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
        # S6
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
        # S7
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
        # S8
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]


    # map table
    TABLES = {
        "IP_TABLE": IP_TABLE,
        "FP_TABLE": FP_TABLE,
        "EXPANSION_TABLE": EXPANSION_TABLE,
        "P_TABLE": P_TABLE,
        "PC1_TABLE": PC1_TABLE,
        "PC2_TABLE": PC2_TABLE,
        "SHIFT_SCHEDULE": SHIFT_SCHEDULE,
        "S_BOXES": S_BOXES
    }

    
    
    def __init__(self):
        pass

    def generate_key(self):
        # Generate a 64-bit key (56 bits random + 8 bits parity)
        key = ''
        for i in range(56):  # 56 random bits
            key += str(random.randint(0, 1))
        key = key.ljust(64, '0')  # Pad to 64 bits
        return key
    
    def pad_text(self, text):
        # Pad the text to be a multiple of 8 characters (64 bits)
        padding_length = 8 - (len(text) % 8)
        padding = chr(padding_length) * padding_length
        return text + padding

    def unpad_text(self, text):
        # Remove padding from the text
        padding_length = ord(text[-1])
        return text[:-padding_length]

    def permute_key(self, key, table_name):
        table = getattr(self, table_name)  # Access class attribute based on table_name
        if len(key) < max(table):
            raise ValueError(f"Key is too short. Expected at least {max(table)} characters, got {len(key)}")
        return ''.join(key[i-1] for i in table)

    def split_key(self, key):
        return key[:len(key)//2], key[len(key)//2:]

    def expansion(self, key):
        expanded_output = ''
        for i in self.EXPANSION_TABLE:
            expanded_output += key[i - 1]
        return expanded_output

    @staticmethod
    def left_shift(key, shifts):
        return key[shifts:] + key[:shifts]

    def generate_subkeys(self, original_key):
        permuted_key = ''.join(original_key[self.PC1_TABLE[i] - 1] for i in range(56))
        left_half, right_half = permuted_key[:28], permuted_key[28:]
        subkeys = []
        for round_shift in self.SHIFT_SCHEDULE:
            left_half = self.left_shift(left_half, round_shift)
            right_half = self.left_shift(right_half, round_shift)
            combined_key = left_half + right_half
            subkey = ''.join(combined_key[self.PC2_TABLE[i] - 1] for i in range(48))
            subkeys.append(subkey)
        return subkeys

    def substitution(self, s_input):
        output = ''
        for i in range(8):
            block = s_input[i*6:(i+1)*6]
            row = int(block[0] + block[5], 2)
            col = int(block[1:5], 2)
            output += format(self.S_BOXES[i][row*16 + col], '04b')
        return output

    def round(self, L_key, R_key, subkeys, round_number):
        current_subkey = subkeys[round_number-1]
        expanded_R_key = self.expansion(R_key)
        xor_output = format(int(expanded_R_key, 2) ^ int(current_subkey, 2), '048b')
        substituted = self.substitution(xor_output)
        permuted = self.permute_key(substituted, "P_TABLE")
        new_R_key = format(int(permuted, 2) ^ int(L_key, 2), '032b')
        new_L_key = R_key
        return new_L_key, new_R_key

    def final_permutation(self, combined_data):
        return ''.join(combined_data[self.FP_TABLE[i] - 1] for i in range(64))
    
    def text_to_binary(self, text):
        # Convert text to binary
        return ''.join(format(ord(x), '08b') for x in text)

    def binary_to_text(self, binary_data):
        text = ''.join(chr(int(binary_data[i:i+8], 2)) for i in range(0, len(binary_data), 8))
        return text
    def des_encrypt(self, plaintext_binary, key_64_bit):
        subkeys = self.generate_subkeys(key_64_bit)
        initial_permutation = self.permute_key(plaintext_binary, "IP_TABLE")
        L_key, R_key = self.split_key(initial_permutation)
        for round_number in range(1, 17):
            L_key, R_key = self.round(L_key, R_key, subkeys, round_number)
        combined_data = R_key + L_key
        final_data = self.final_permutation(combined_data)
        return final_data

    def des_decrypt(self, ciphertext_binary, key_64_bit):
        subkeys = self.generate_subkeys(key_64_bit)
        subkeys = subkeys[::-1]
        initial_permutation = self.permute_key(ciphertext_binary, "IP_TABLE")
        L_key, R_key = self.split_key(initial_permutation)
        for round_number in range(1, 17):
            L_key, R_key = self.round(L_key, R_key, subkeys, round_number)
        combined_data = R_key + L_key
        final_data = self.final_permutation(combined_data)
        return final_data

    def encrypt(self, text, key_64_bit):
        plaintext_binary = self.text_to_binary(text)
        encrypted_binary = self.des_encrypt(plaintext_binary, key_64_bit)
        return encrypted_binary

    def decrypt(self, binary_data, key_64_bit):
        decrypted_binary = self.des_decrypt(binary_data, key_64_bit)
        decrypted_text = self.binary_to_text(decrypted_binary)
        return decrypted_text

# Usage example
if __name__ == '__main__':
    des = DES()
    text = "heasrdfdf"
    key = des.generate_key()

    encrypted_data = des.encrypt(text, key)
    print("Encrypted data:", encrypted_data)

    decrypted_text = des.decrypt(encrypted_data, key)
    print("Decrypted text:", decrypted_text)