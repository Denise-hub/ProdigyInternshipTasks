# Image Encryption and Decryption Program
# Author: <Den>
# This script allows users to encrypt or decrypt an image using a simple key-based method.

from PIL import Image  # type: ignore # For image handling  "C:\Users\Admin\Pictures\saved"
import os

def encrypt_image(input_path, output_path, key):
    """
    Encrypts an image by adjusting its pixel values using a key.

    Parameters:
        input_path (str): Path to the input image.
        output_path (str): Path to save the encrypted image.
        key (int): The encryption key (a number).
    """
    try:
        # Open the input image
        image = Image.open(input_path)
        pixels = image.load()
        width, height = image.size

        # Iterate over each pixel and encrypt it
        for x in range(width):
            for y in range(height):
                r, g, b = pixels[x, y]
                pixels[x, y] = ((r + key) % 256, (g + key) % 256, (b + key) % 256)

        # Check and ensure the output file has a valid image extension
        if not output_path.lower().endswith(('.png', '.jpg', '.jpeg')):
            print("Error: Output file must have a valid image extension (e.g., .jpg, .png).")
            return

        # Save the encrypted image
        image.save(output_path)
        print(f"Image encrypted successfully and saved to {output_path}.")
    except FileNotFoundError:
        # Error if the input file doesn't exist
        print(f"Error: The file '{input_path}' was not found.")
    except Exception as e:
        # Catch any other unexpected errors
        print(f"Error: {e}")


def decrypt_image(input_path, output_path, key):
    """
    Decrypts an image by reversing the encryption process.

    Parameters:
        input_path (str): Path to the input encrypted image.
        output_path (str): Path to save the decrypted image.
        key (int): The decryption key (a number).
    """
    try:
        # Open the encrypted image
        image = Image.open(input_path)
        pixels = image.load()
        width, height = image.size

        # Iterate over each pixel and decrypt it
        for x in range(width):
            for y in range(height):
                r, g, b = pixels[x, y]
                pixels[x, y] = ((r - key) % 256, (g - key) % 256, (b - key) % 256)

        # Check and ensure the output file has a valid image extension
        if not output_path.lower().endswith(('.png', '.jpg', '.jpeg')):
            print("Error: Output file must have a valid image extension (e.g., .jpg, .png).")
            return

        # Save the decrypted image
        image.save(output_path)
        print(f"Image decrypted successfully and saved to {output_path}.")
    except FileNotFoundError:
        # Error if the input file doesn't exist
        print(f"Error: The file '{input_path}' was not found.")
    except Exception as e:
        # Catch any other unexpected errors
        print(f"Error: {e}")


# Main function to handle user interaction
if __name__ == "__main__":
    print("Simple Image Encryption Tool")
    choice = input("Do you want to (1) Encrypt or (2) Decrypt an image? Enter 1 or 2: ").strip()

    # Validate user choice
    if choice not in ("1", "2"):
        print("Invalid choice. Please run the program again.")
        exit()

    # Get the input image path
    input_path = input("Enter the path to the input image: ").strip()
    if not os.path.exists(input_path):
        print(f"Error: The specified image file does not exist at: {input_path}")
        exit()

    # Get the output file path
    output_path = input("Enter the path to save the output image (with file extension): ").strip()
    if not output_path:
        print("Error: Output path cannot be empty.")
        exit()

    # Get the encryption/decryption key
    key = input("Enter the encryption/decryption key (a number): ").strip()
    if not key.isdigit():
        print("Error: Key must be a positive integer.")
        exit()

    # Convert the key to an integer
    key = int(key)

    # Perform encryption or decryption based on user choice
    if choice == "1":
        encrypt_image(input_path, output_path, key)
    elif choice == "2":
        decrypt_image(input_path, output_path, key)
