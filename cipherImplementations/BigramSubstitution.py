import numpy as np
from cipherImplementations.cipher import Cipher

class BigramSubstitution(Cipher):
    def __init__(self, alphabet, unknown_symbol, unknown_symbol_number):
        self.alphabet = alphabet
        self.unknown_symbol = unknown_symbol
        self.unknown_symbol_number = unknown_symbol_number
        

    # a property to adhere to the base class structure
    @property
    def needs_plaintext_of_specific_length(self):
        return False

    def generate_random_key(self, length=None):
        # The key is a permutation of all 676 possible bigrams.
        # Mapping: Input Bigram Index -> Output Bigram Index
        key = np.arange(676)
        np.random.shuffle(key)
        return key

    def encrypt(self, plaintext, key):
        # plaintext: List/Array of numbers (0-25)
        # key: Array with 676 numbers 
        
        ciphertext = []
        text_len = len(plaintext)
        
        # Padding: Text must have even length
        working_text = list(plaintext)
        if text_len % 2 != 0:
            # If 23 (X) is not in the alphabet, take 0 (A)
            padding_char = 23 if 23 < len(self.alphabet) else 0
            working_text.append(padding_char)

        # 2. Encryption in Bigrams
        for i in range(0, len(working_text), 2):
            char1 = working_text[i]
            char2 = working_text[i+1]
            
            # Pass through unknown characters
            if char1 == self.unknown_symbol_number or char2 == self.unknown_symbol_number:
                ciphertext.extend([self.unknown_symbol_number, self.unknown_symbol_number])
                continue

            # Bigram to Index
            bigram_index = char1 * 26 + char2
            
            # Perform substitution
            new_bigram_index = key[bigram_index]
            
            # Convert back to two characters
            new_char1 = new_bigram_index // 26
            new_char2 = new_bigram_index % 26
            
            ciphertext.extend([new_char1, new_char2])
            
        return np.array(ciphertext)

    def decrypt(self, ciphertext, key):
        # ciphertext: Array of numbers
        # key: Array of 676 numbers 

        plaintext = []
        
        # Create inverse key (Lookup: Which original bigram mapped to X?)
        # key[original] = encrypted  =>  inv_key[encrypted] = original
        inv_key = np.zeros(676, dtype=int)
        inv_key[key] = np.arange(676)

        # Decryption in steps of 2
        for i in range(0, len(ciphertext), 2):
            # check for odd lengths 
            if i + 1 >= len(ciphertext):
                break

            char1 = ciphertext[i]
            char2 = ciphertext[i+1]

            # Pass through unknown characters
            if char1 == self.unknown_symbol_number or char2 == self.unknown_symbol_number:
                plaintext.extend([self.unknown_symbol_number, self.unknown_symbol_number])
                continue

            
            bigram_index = char1 * 26 + char2
            
            # Inverse substitution
            orig_bigram_index = inv_key[bigram_index]
            
            # Convert back to two characters
            orig_char1 = orig_bigram_index // 26
            orig_char2 = orig_bigram_index % 26
            
            plaintext.extend([orig_char1, orig_char2])
            
        return np.array(plaintext)

    def filter(self, plaintext, keep_unknown_symbols):
        # Standard filtering
        if not keep_unknown_symbols:
            return plaintext.lower().translate(str.maketrans('', '', ''.join(c for c in map(chr, range(256)) if bytes([c]) not in self.alphabet)))
        return plaintext