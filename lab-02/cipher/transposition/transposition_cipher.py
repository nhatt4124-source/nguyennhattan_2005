class TranspositionCipher:
    def __init__(self):
        pass

    def encrypt(self, text, key):
        encrypted_text = ''
        for col in range(key):
            pointer = col
            while pointer < len(text):
                encrypted_text += text[pointer]
                pointer += key
        return encrypted_text

    def decrypt(self, text, key):
        decrypted_text = [''] * len(text)
        col = 0
        pointer = 0
        for i in range(len(text)):
            decrypted_text[pointer] = text[i]
            pointer += key
            if pointer >= len(text):
                col += 1
                pointer = col
        return ''.join(decrypted_text)
