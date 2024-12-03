# Aes_tool
[![.NET](https://github.com/Evgeniy20181/Aes_tools/actions/workflows/dotnet.yml/badge.svg)](https://github.com/Evgeniy20181/Aes_tools/actions/workflows/dotnet.yml)

Here’s a sample `README.md` file for your project:


# AES Encryption/Decryption Tool

A command-line application for securely encrypting and decrypting files using the AES (Advanced Encryption Standard) algorithm.

---

## Features
- **AES Encryption**: Protect files with strong encryption.
- **AES Decryption**: Decrypt files back to their original form.
- **Config File Management**: Automatically generate or load encryption configuration, including salt and initialization vector (IV).
- **Password-Based Key Derivation**: Generate AES keys securely using PBKDF2 with a user-provided password.

---

## Prerequisites
- [.NET SDK](https://dotnet.microsoft.com/download) (version 8.0 or higher)

---

## Usage

### 1. Clone the Repository
```bash
git clone https://github.com/Evgeniy20181/Aes_tool/
```

### 2. Build the Project
```bash
dotnet build
```

### 3. Run the Application
```bash
dotnet run
```

### 4. Follow the On-Screen Instructions
- Provide a strong password (at least 8 characters) to generate an AES key.
- Choose between file encryption and decryption.
- Enter the file path for processing.
- The output file will be saved in the same directory as the original file with `_encrypted` or `_decrypted` appended to its name.

---

## Configuration
- The application generates a `config.json` file if it doesn't already exist.
- The `config.json` file contains:
  - **Salt**: Used for key derivation.
  - **IV (Initialization Vector)**: Ensures uniqueness in encryption.

Example `config.json`:
```json
{
  "Salt": "some_base64_encoded_salt",
  "IV": "some_base64_encoded_iv"
}
```

---

## Code Structure
- **`EncryptionConfig`**: Represents the configuration for encryption, including salt and IV.
- **`Aes_tools`**: Contains helper methods for AES operations such as encryption, decryption, key derivation, and file handling.
- **`Program`**: Main entry point of the application that handles user interaction.

---

## Example Workflow
1. Generate or load a configuration file (`config.json`).
2. Derive an AES key using a password and the salt from the config file.
3. Encrypt or decrypt a file based on user input.

---

## Security Notes
- **Password Strength**: Use a strong password for better security.
- **Config Sharing**: The `config.json` file can be shared but avoid sharing passwords or sensitive data.
- **File Safety**: Ensure secure storage of encrypted files and key material.

---

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Contribution
Feel free to fork this repository and submit pull requests to improve the functionality or fix bugs. Suggestions and feedback are welcome!

---

## Contact
For any questions or issues, feel free to reach out through the repository's [issue tracker](https://github.com/Evgeniy20181/Aes_tool/issues).
