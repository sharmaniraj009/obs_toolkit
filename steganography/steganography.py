from PIL import Image
import numpy as np

def encode_image(input_image, message, output_image):
    img = Image.open(input_image)
    img = img.convert("RGB")
    data = np.array(img)
    
    binary_message = ''.join(format(ord(c), '08b') for c in message) + '00000000'  # Null terminator
    index = 0

    for row in data:
        for pixel in row:
            for i in range(3):  # RGB channels
                if index < len(binary_message):
                    pixel[i] = (pixel[i] & 0xFE) | int(binary_message[index])
                    index += 1

    encoded_img = Image.fromarray(data)
    encoded_img.save(output_image)
    print(f"[SUCCESS] Data hidden in {output_image}")

def decode_image(encoded_image):
    img = Image.open(encoded_image)
    data = np.array(img)
    binary_message = ""
    
    for row in data:
        for pixel in row:
            for i in range(3):
                binary_message += str(pixel[i] & 1)
    
    bytes_list = [binary_message[i:i+8] for i in range(0, len(binary_message), 8)]
    message = "".join(chr(int(byte, 2)) for byte in bytes_list if int(byte, 2) != 0)
    return message

def encode_whitespace(message):
    binary_message = ''.join(format(ord(c), '08b') for c in message)
    whitespace_message = binary_message.replace('0', '\u200B').replace('1', '\u200C')
    return whitespace_message

def decode_whitespace(encoded_text):
    binary_message = encoded_text.replace('\u200B', '0').replace('\u200C', '1')
    bytes_list = [binary_message[i:i+8] for i in range(0, len(binary_message), 8)]
    message = "".join(chr(int(byte, 2)) for byte in bytes_list)
    return message