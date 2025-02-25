# ShadowCrypt 🛡️ - Secure Your Files with Encryption & Steganography  

![ShadowCrypt](/Output/Result.jpg)  

## 🔒 About ShadowCrypt 🛡️
ShadowCrypt is a powerful cybersecurity tool that combines **AES encryption** and **steganography** to securely hide sensitive files within images. Designed with privacy and security in mind, it provides a seamless way to protect your data while maintaining confidentiality and integrity.  

## 🚀 Features  
- **AES-256 Encryption**: Ensures robust data protection with industry-standard encryption.  
- **Steganography**: Conceals encrypted files inside images, making them undetectable.  
- **Password-Based Encryption**: Secure access using a user-defined password.  
- **HMAC Integrity Check**: Verifies data integrity and prevents tampering.  
- **Stealth Mode**: Optionally hides files within decoy images for extra security.  
- **User-Friendly UI**: Intuitive interface for easy file hiding and extraction.  

## 🛠️ How It Works  
1. **Select a File**: Choose the file you want to encrypt and hide.  
2. **Encrypt & Embed**: ShadowCrypt encrypts the file and embeds it within an image.  
3. **Extract & Decrypt**: The hidden file can be extracted and decrypted with the correct password.  

## 📷 Example Usage  
```sh  
# Hide a file within an image  
python shadowcrypt.py --hide -i cover_image.png -f secret.txt -p mypassword123  

# Extract the hidden file  
python shadowcrypt.py --extract -i cover_image.png -p mypassword123  

# Hide a file in stealth mode using a decoy image  
python shadowcrypt.py --hide -i cover_image.png -f secret.txt -p mypassword123 --stealth decoy_image.png  

# Extract a file from a stealth mode image  
python shadowcrypt.py --extract -i decoy_image.png -p mypassword123 --stealth  
```

## 🏆 Why Choose ShadowCrypt?  
✅ **Secure** – AES-256 encryption guarantees strong protection.  
✅ **Undetectable** – Steganography makes your data invisible.  
✅ **Fast & Lightweight** – Efficient encryption and hiding process.  
✅ **Open-Source** – Transparent and customizable for developers.  
- **Stealth Mode**: Enhances security by embedding files into decoy images, making detection nearly impossible.

## 📌 Requirements  
- Python 3.x  
- Pillow (for image processing)  
- PyCryptodome (for encryption)  

## 📥 Installation  
```sh  
git clone https://github.com/jpravin664/ShadowCrypt 
cd ShadowCrypt  
```
- Install the require modules and libraries 

## 💡 Future Enhancements  
- GUI version for a more user-friendly experience.  
- Support for additional file formats.  
- Mobile app integration.  

## 🎓 Contributors  
- [Pravin](https://github.com/jpravin664)( myself)
- [Pranav](https://github.com/OGpranav17)  
- [Praveen](https://github.com/PRAVEENM16)  

## 📜 License  
This project is licensed under the **MIT License**. Feel free to use and contribute!  

---  
⭐ **Star this repo** if you like it! Contributions & feedback are welcome.  

