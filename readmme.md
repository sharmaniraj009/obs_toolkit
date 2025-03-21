# Multi-Layer Obfuscation & Steganography Toolkit

## Overview
This toolkit provides **multi-layer obfuscation** and **steganographic encoding** techniques for securing sensitive data. It supports various obfuscation methods, including **Base64, XOR, Steganography (Image & Whitespace)**.

## Features
✅ **Multi-layer obfuscation:** Base64, XOR
✅ **Image-based Steganography:** Hide text inside images using LSB encoding
✅ **Whitespace-based Steganography:** Hide data using zero-width characters
✅ **Binary file support**
✅ **Custom XOR keys**
✅ **Command-Line Interface (CLI) Support**

---

## Installation

### **Dependencies**
Install the required dependencies using:
```bash
pip install -r requirements.txt
```
Ensure you have `PIL` (Pillow) and `numpy` installed for image processing.

---

## Usage

### **Obfuscation**
#### **Basic Obfuscation (Base64, XOR)**
```bash
python main.py obfuscate secret.txt --methods base64,xor
```
#### **Obfuscation with a Custom XOR Key**
```bash
python main.py obfuscate secret.txt --methods xor --key mysecretkey
```

### **Deobfuscation**
```bash
python main.py deobfuscate secret.txt.obf --methods xor,base64
```

---

## **Steganography Support**

### **Image Steganography**
#### **Hide Text in Image**
```bash
python main.py obfuscate secret.txt --methods steg-image --image input.png --output stego.png
```
#### **Extract Text from Image**
```bash
python main.py deobfuscate stego.png --methods steg-image
```

### **Whitespace Steganography**
#### **Hide Data in Whitespace Characters**
```bash
python main.py obfuscate secret.txt --methods whitespace
```
#### **Extract Data from Whitespace**
```bash
python main.py deobfuscate secret.txt.steg --methods whitespace
```

---

## **Project Structure**
```
obs_toolkit/
│── obfuscate/
│   ├── obfuscator.py
│── deobfuscate/
│   ├── deobfuscator.py
│── steg/
│   ├── steganography.py
│── main.py
│── requirements.txt
│── README.md
```

---

## **Future Enhancements**
🔹 **Audio Steganography** (Hiding text in sound files)  
🔹 **Network Traffic Obfuscation**  
🔹 **Polyglot File Obfuscation**  

---

## **Contributing**
Feel free to open an issue or submit a pull request to improve the toolkit!

---

## **License**
This project is licensed under the **MIT License**.

