import numpy as np
from cipherImplementations.cipher import Cipher

class BigramSubstitution(Cipher):
    def __init__(self, alphabet, unknown_symbol, unknown_symbol_number):
        self.alphabet = alphabet
        self.unknown_symbol = unknown_symbol
        self.unknown_symbol_number = unknown_symbol_number
        
        self.needs_plaintext_of_specific_length = False

    def generate_random_key(self, length=None):
        # Key is a permutation of all possible bigrams 
        # Bigrams as number represantation
        key = np.arange(676)
        np.random.shuffle(key)
        return key

    def encrypt(self, plaintext, key):
        # plaintext: lis of numbers
        # key: Array with 676 elements)
        
        ciphertext = []
        
        # 1. Text has to be out of even number of characters, x as placeholder
        text_len = len(plaintext)
        working_text = list(plaintext)
        if text_len % 2 != 0:
            working_text.append(23)

        # 2. Encryption in bigrams
        for i in range(0, len(working_text), 2):
            char1 = working_text[i]
            char2 = working_text[i+1]
            if char1 == self.unknown_symbol_number or char2 == self.unknown_symbol_number:
                ciphertext.extend([self.unknown_symbol_number, self.unknown_symbol_number])
                continue

            
            bigram_index = char1 * 26 + char2
            
            # B. apply Substitution 
            new_bigram_index = key[bigram_index]
            
           
            new_char1 = new_bigram_index // 26
            new_char2 = new_bigram_index % 26
            
            ciphertext.extend([new_char1, new_char2])
            
        return np.array(ciphertext)

    def filter(self, plaintext, keep_unknown_symbols):
        
        if not keep_unknown_symbols:
            return plaintext.lower().translate(str.maketrans('', '', ''.join(c for c in map(chr, range(256)) if bytes([c]) not in self.alphabet)))
        return plaintext