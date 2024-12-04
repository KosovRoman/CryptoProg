#include <iostream>
#include <fstream>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>

void encryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& password) {
    using namespace CryptoPP;
    byte key[AES::DEFAULT_KEYLENGTH], iv[AES::BLOCKSIZE];

    // Derive key and IV from the password
    SHA256().CalculateDigest(key, (const byte*)password.data(), password.size());
    std::memset(iv, 0x00, AES::BLOCKSIZE); // For simplicity, using zero IV. Avoid in production.

    try {
        CBC_Mode<AES>::Encryption encryptor(key, sizeof(key), iv);

        FileSource(inputFile.c_str(), true,
            new StreamTransformationFilter(encryptor,
                new FileSink(outputFile.c_str())
            )
        );

        std::cout << "File encrypted successfully: " << outputFile << std::endl;
    } catch (const Exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

void decryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& password) {
    using namespace CryptoPP;
    byte key[AES::DEFAULT_KEYLENGTH], iv[AES::BLOCKSIZE];

    // Derive key and IV from the password
    SHA256().CalculateDigest(key, (const byte*)password.data(), password.size());
    std::memset(iv, 0x00, AES::BLOCKSIZE); // For simplicity, using zero IV. Avoid in production.

    try {
        CBC_Mode<AES>::Decryption decryptor(key, sizeof(key), iv);

        FileSource(inputFile.c_str(), true,
            new StreamTransformationFilter(decryptor,
                new FileSink(outputFile.c_str())
            )
        );

        std::cout << "File decrypted successfully: " << outputFile << std::endl;
    } catch (const Exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] << " <mode> <input file> <output file> <password>" << std::endl;
        std::cerr << "Mode: encrypt | decrypt" << std::endl;
        return 1;
    }

    std::string mode = argv[1];
    std::string inputFile = argv[2];
    std::string outputFile = argv[3];
    std::string password = argv[4];

    if (mode == "encrypt") {
        encryptFile(inputFile, outputFile, password);
    } else if (mode == "decrypt") {
        decryptFile(inputFile, outputFile, password);
    } else {
        std::cerr << "Invalid mode. Use 'encrypt' or 'decrypt'." << std::endl;
        return 1;
    }

    return 0;
}

