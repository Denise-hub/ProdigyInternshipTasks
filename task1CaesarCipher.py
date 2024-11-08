def caesar_cipher(text, shift, mode='encrypt'):
    # Ensure shift value is within the 0-25 range
    shift = shift % 26
    # Reverse shift for decryption
    if mode == 'decrypt':
        shift = -shift
    
    result = ""
    # Iterate through each character in the text
    for char in text:
        # Encrypt uppercase letters
        if char.isupper():
            new_char = chr((ord(char) - 65 + shift) % 26 + 65)
            result += new_char
        # Encrypt lowercase letters
        elif char.islower():
            new_char = chr((ord(char) - 97 + shift) % 26 + 97)
            result += new_char
        # Leave non-alphabet characters unchanged
        else:
            result += char
    return result

# Main program to interact with the user
def main():
    print("Caesar Cipher Program")
    message = input("Enter the message: ")
    shift = int(input("Enter the shift value (integer): "))
    mode = input("Choose mode: 'encrypt' or 'decrypt': ").strip().lower()

    # Validate mode input
    if mode not in ['encrypt', 'decrypt']:
        print("Invalid mode selected. Please enter 'encrypt' or 'decrypt'.")
        return
    
    # Perform encryption or decryption based on mode
    result = caesar_cipher(message, shift, mode)
    print(f"Result ({mode}ed message): {result}")

# Run the main program
if __name__ == "__main__":
    main()
