# Let;s use pillow library for image handling
from PIL import Image
import os

def encrypt_image(input_path, output_path, key):
    """Encrypt an image by modifying its pixel values."""
    try:
        image = Image.open(input_path)
        pixels = image.load()
        width, height = image.size

        for x in range(width):
            for y in range(height):
                r, g, b = pixels[x, y]
                # Encrypt each pixel
                pixels[x, y] = ((r + key) % 256, (g + key) % 256, (b + key) % 256)

        image.save(output_path)
        print(f"Image encrypted successfully and saved to {output_path}.")
    except Exception as e:
        print(f"Error: {e}")

def decrypt_image(input_path, output_path, key):
    """Decrypt an image by reversing the pixel value modification."""
    try:
        image = Image.open(input_path)
        pixels = image.load()
        width, height = image.size

        for x in range(width):
            for y in range(height):
                r, g, b = pixels[x, y]
                # Decrypt each pixel
                pixels[x, y] = ((r - key) % 256, (g - key) % 256, (b - key) % 256)

        image.save(output_path)
        print(f"Image decrypted successfully and saved to {output_path}.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    print("Simple Image Encryption Tool")
    choice = input("Do you want to (1) Encrypt or (2) Decrypt an image? Enter 1 or 2: ").strip()

    if choice not in ("1", "2"):
        print("Invalid choice. Please run the program again.")
        exit()

    input_path = input("Enter the path to the input image: ").strip()
    if not os.path.exists(input_path):
        print("The specified image file does not exist.")
        exit()

    output_path = input("Enter the path to save the output image: ").strip()
    key = int(input("Enter the encryption/decryption key (a number): ").strip())

    if choice == "1":
        encrypt_image(input_path, output_path, key)
    elif choice == "2":
        decrypt_image(input_path, output_path, key)
