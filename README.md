# 🔐 Advanced Caesar Cipher + AES Image Encryptor

A comprehensive desktop application that combines classical Caesar cipher text encryption with modern AES image encryption techniques. This tool provides both educational insight into cryptography and practical image security solutions.

## 📋 Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Technologies Used](#technologies-used)
- [Installation](#installation)
- [Usage Guide](#usage-guide)
- [Encryption Methods](#encryption-methods)
- [Security Features](#security-features)
- [File Structure](#file-structure)
- [Screenshots](#screenshots)
- [Contributing](#contributing)
- [License](#license)

## 🎯 Overview

This application demonstrates the evolution of cryptography from classical methods (Caesar cipher) to modern encryption standards (AES). It's designed for:

- **Educational purposes**: Understanding different encryption techniques
- **Practical security**: Protecting sensitive images with military-grade encryption
- **Cryptography enthusiasts**: Exploring various AES modes and implementations
- **Privacy-conscious users**: Securing personal photos and documents

## ✨ Features

### 🔤 Caesar Cipher Module
- **Text encryption/decryption** using classical shift cipher
- **Variable shift values** for customizable security
- **Bidirectional processing** (encrypt ↔ decrypt)
- **Real-time text processing** with immediate results
- **Preserves non-alphabetic characters** (numbers, symbols, spaces)

### 🖼️ Advanced AES Image Encryption

#### Two Encryption Approaches:
1. **File-Level Encryption** 🗂️
   - Encrypts entire image file as binary data
   - Maximum security with complete file obfuscation
   - Supports all image formats (JPEG, PNG, BMP, TIFF)
   - Creates `.aes` encrypted files

2. **Pixel-Level Encryption** 🎨
   - Encrypts image pixel data for visual scrambling effect
   - Creates visually scrambled images
   - Maintains image format and dimensions
   - Demonstrates encryption visually

#### Multiple AES Modes:
- **CBC Mode** (Cipher Block Chaining) - Industry standard, highly secure
- **GCM Mode** (Galois/Counter Mode) - Authenticated encryption with integrity verification
- **ECB Mode** (Electronic Codebook) - Simple mode for educational comparison

### 🛡️ Security Features
- **PBKDF2 Key Derivation** - 100,000 iterations for password hardening
- **Random Salt Generation** - Prevents rainbow table attacks
- **Initialization Vectors** - Ensures encryption uniqueness
- **Authentication Tags** (GCM mode) - Verifies data integrity
- **Password Verification** - Hash-based password checking
- **Secure Metadata Storage** - Encrypted parameters preservation

### 🖥️ User Interface Features
- **Intuitive GUI** with tabbed interface
- **Real-time image preview** (Original → Encrypted → Decrypted)
- **Drag-and-drop file selection**
- **Progress indicators** for large files
- **Error handling** with user-friendly messages
- **Cross-platform compatibility** (Windows, macOS, Linux)

## 🛠️ Technologies Used

### Core Technologies
| Technology | Purpose | Version |
|------------|---------|---------|
| **Python** | Main programming language | 3.8+ |
| **Tkinter** | GUI framework (cross-platform) | Built-in |
| **PIL/Pillow** | Image processing and manipulation | 10.0+ |
| **PyCryptodome** | Advanced cryptographic functions | 3.19+ |

### Cryptographic Libraries
- **AES (Advanced Encryption Standard)** - Military-grade symmetric encryption
- **PBKDF2** - Password-Based Key Derivation Function 2
- **SHA-256** - Cryptographic hash function for password verification
- **Secure Random** - Cryptographically secure random number generation

### Why These Technologies?

#### **Python + Tkinter**
- **Cross-platform compatibility** - Runs on Windows, macOS, Linux
- **Built-in GUI** - No additional dependencies for basic interface
- **Rapid development** - Quick prototyping and iteration
- **Educational value** - Clear, readable code for learning

#### **PIL/Pillow**
- **Universal image support** - Handles all major image formats
- **Memory efficiency** - Optimized image processing
- **Pixel manipulation** - Direct access to image data
- **Format conversion** - Seamless format handling

#### **PyCryptodome**
- **Industry standard** - Implements proven cryptographic algorithms
- **Multiple AES modes** - CBC, GCM, ECB support
- **Secure implementation** - Resistant to timing attacks
- **Well-documented** - Extensive cryptographic primitives

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Step-by-Step Installation

1. **Clone the repository**
   ```bash
   https://github.com/garurmaga/Text-Encryption-Using-Cryptographic-Algorithms.git
   cd Advanced-Caesar-Cipher-AES-Image-Encryptor
   ```

2. **Create virtual environment** (recommended)
   ```bash
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**
   ```bash
   python main.py
   ```

### Requirements.txt
```
Pillow>=10.0.0
pycryptodome>=3.19.0
```

## 📖 Usage Guide

### Caesar Cipher Usage

1. **Text Input**: Enter your text in the input field
2. **Set Shift Value**: Choose a number (1-25) for character shifting
3. **Select Mode**: Choose "Encrypt" or "Decrypt"
4. **Process**: Click "Process" to see results instantly

**Example:**
```
Original: "Hello World"
Shift: 3
Encrypted: "Khoor Zruog"
```

### AES Image Encryption Usage

#### File Encryption (Recommended for Security)
1. **Select Image**: Click "📁 Select Image" to choose your file
2. **Enter Password**: Type a strong password
3. **Choose AES Mode**: Select CBC (recommended) or GCM
4. **Encrypt**: Click "🔒 Encrypt as File"
5. **Result**: Encrypted `.aes` file is created

#### Pixel Scrambling (Visual Effect)
1. **Select Image**: Choose your image file
2. **Enter Password**: Set encryption password
3. **Scramble**: Click "🎨 Scramble Pixels"
4. **View**: See the visually scrambled result

#### Decryption Process
1. **Select Encrypted File**: Choose `.aes` file or scrambled image
2. **Enter Password**: Provide the correct decryption password
3. **Decrypt**: Click appropriate decrypt button
4. **Verify**: View the restored original image

## 🔒 Encryption Methods

### Caesar Cipher (Educational)
**Algorithm**: Simple substitution cipher
```
Encryption: E(x) = (x + k) mod 26
Decryption: D(x) = (x - k) mod 26
```
**Use Case**: Understanding basic cryptographic concepts
**Security**: Low (easily breakable, historical significance)

### AES Encryption (Professional)

#### File-Level AES Encryption
```
1. Password → PBKDF2 → 256-bit Key
2. Generate random IV/Salt
3. Encrypt entire file with AES
4. Save encrypted data + metadata
```


#### Pixel-Level AES Encryption
```
1. Extract RGB pixel data
2. Convert to byte array
3. Encrypt pixel bytes with AES-ECB
4. Reconstruct scrambled image
```
**Use Case**: Visual demonstration of encryption effects

### AES Modes Comparison

| Mode | Security | Speed | Use Case |
|------|----------|-------|----------|
| **CBC** | High | Fast | General purpose, file encryption |
| **GCM** | Highest | Medium | Authenticated encryption, integrity critical |
| **ECB** | Low | Fastest | Educational, visual effects only |

## 🔐 Security Features

### Password Security
- **PBKDF2 with 100,000 iterations** - Slows down brute force attacks
- **Random salt generation** - Prevents precomputed hash attacks
- **SHA-256 password hashing** - Secure password verification

### Encryption Security
- **256-bit AES encryption** - NSA Suite B approved
- **Initialization vectors** - Prevents pattern analysis
- **Proper padding** - PKCS7 standard implementation
- **Authenticated encryption** (GCM mode) - Detects tampering

### Implementation Security
- **Secure random generation** - Cryptographically secure randomness
- **Memory management** - Sensitive data clearing
- **Error handling** - No information leakage in errors

## 📁 File Structure

```
caesar-aes-encryptor/
│
├── main.py                 # Main application file
├── requirements.txt        # Python dependencies
├── README.md              # This documentation
├── LICENSE                # License file
│
├── assets/                # Application assets
│   ├── screenshots/       # Application screenshots
│   └── icons/            # Application icons
│
├── tests/                 # Unit tests
│   ├── test_caesar.py    # Caesar cipher tests
│   ├── test_aes.py       # AES encryption tests
│   └── test_gui.py       # GUI tests
│
├── docs/                  # Additional documentation
│   ├── SECURITY.md       # Security considerations
│   ├── CONTRIBUTING.md   # Contribution guidelines
│   └── CHANGELOG.md      # Version history
│
└── examples/             # Example files
    ├── sample_images/    # Test images
    └── encrypted_samples/ # Sample encrypted files
```

## 🖼️ Screenshots

### Main Interface
![Main Interface](https://github.com/user-attachments/assets/7d597a4f-3399-48fc-bef6-b5e517d9e519)


### Caesar Cipher Module
![Caesar Cipher](![Caesar Cipher Module](https://github.com/user-attachments/assets/c93373fb-cee8-4a92-a5de-f39f44f378a2)


### AES Image Encryption
![AES Encryption](![choosing for encryption image](https://github.com/user-attachments/assets/f8100ccd-a220-4966-be95-baaa58a8827c)

### Scramble the Encryption Image
![Scramble Image]![It is process in which the encrypted image to scramble it ](https://github.com/user-attachments/assets/364cef49-5c49-433e-be65-bb0e68e60198)


### Encryption Process to decrypt image and unscramble it
![Encryption Process](![Decrypted the image and unscramble it](https://github.com/user-attachments/assets/2bb73ad5-2fa7-4bd9-ba0a-10dd0321023a)
 

## 🎯 Use Cases

### Educational Applications
- **Cryptography courses** - Demonstrate classical vs modern encryption
- **Computer science education** - Practical cryptography implementation
- **Security awareness training** - Show encryption importance

### Practical Applications
- **Personal photo protection** - Secure sensitive images
- **Document security** - Protect confidential visual documents
- **Privacy protection** - Secure images before cloud upload
- **Forensic analysis** - Demonstrate encryption effects

### Professional Applications
- **Security consulting** - Demonstrate encryption techniques
- **Software development** - Reference implementation
- **Penetration testing** - Understand encryption strengths/weaknesses

## 🔍 Technical Details

### Performance Metrics
- **File encryption speed**: ~50MB/second (varies by hardware)
- **Pixel encryption**: Real-time for images up to 4K resolution
- **Memory usage**: Minimal (processes images in chunks)
- **Supported file sizes**: Up to 2GB per file

### Compatibility
- **Operating Systems**: Windows 10+, macOS 10.14+, Linux (Ubuntu 18.04+)
- **Python versions**: 3.8, 3.9, 3.10, 3.11, 3.12
- **Image formats**: JPEG, PNG, BMP, TIFF, GIF
- **Architecture**: x86, x64, ARM64

## 🚨 Security Considerations

### Strengths
✅ **Military-grade AES encryption**
✅ **Strong key derivation (PBKDF2)**
✅ **Random salt and IV generation**
✅ **Multiple encryption modes**
✅ **Password verification system**

### Limitations
⚠️ **Password strength dependent** - Weak passwords reduce security
⚠️ **Local storage** - Encrypted files stored locally
⚠️ **GUI application** - Not suitable for automated/batch processing
⚠️ **Single-user design** - No multi-user key management

### Best Practices
1. **Use strong passwords** (12+ characters, mixed case, numbers, symbols)
2. **Keep encrypted files separate** from decryption passwords
3. **Regular backups** of encrypted files
4. **Update dependencies** regularly for security patches

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Install development dependencies (`pip install -r requirements-dev.txt`)
4. Make your changes
5. Run tests (`python -m pytest`)
6. Commit changes (`git commit -m 'Add amazing feature'`)
7. Push to branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Areas for Contribution
- 🔧 **Additional AES modes** (CTR, OFB, CFB)
- 🎨 **UI/UX improvements** - Modern interface design
- 📱 **Mobile version** - React Native or Flutter implementation
- 🔗 **API development** - REST API for programmatic access
- 🧪 **Advanced cryptography** - Elliptic curve, quantum-resistant algorithms
- 📚 **Documentation** - Tutorials, examples, translations

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Python Software Foundation** - For the amazing Python language
- **Pillow Contributors** - For excellent image processing capabilities  
- **PyCryptodome Team** - For robust cryptographic implementations
- **Cryptography Community** - For educational resources and standards
- **Open Source Community** - For inspiration and collaboration

📞 Support

    Issues: https://github.com/garurmaga/Advanced-Caesar-Cipher-AES-Image-Encryptor/issues

    Discussions: https://github.com/garurmaga/Advanced-Caesar-Cipher-AES-Image-Encryptor/discussions

    Email: mailto:abhijeetranjan839@gmail.com

    Documentation (Wiki): https://github.com/garurmaga/Advanced-Caesar-Cipher-AES-Image-Encryptor/wiki

## 🔄 Version History

- **v1.0.0** - Initial release with Caesar cipher and basic AES
- **v1.1.0** - Added multiple AES modes (CBC, GCM, ECB)
- **v1.2.0** - Enhanced UI with three-panel display
- **v1.3.0** - Added pixel-level encryption visualization
- **v2.0.0** - Complete rewrite with advanced security features

---

**⭐ Star this repository if you find it useful!**

**🍴 Fork it to create your own version!**

**📢 Share with others interested in cryptography!**
