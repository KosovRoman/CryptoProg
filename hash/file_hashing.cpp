#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>

void HashFile(const std::string& filename) {
    try {
        std::ifstream file(filename, std::ios::in | std::ios::binary);
        if (!file.is_open()) {
            throw std::runtime_error("Не удалось открыть файл: " + filename);
        }
        file.close();

        CryptoPP::SHA256 hash;

        std::string digest;

        CryptoPP::FileSource(filename.c_str(), true, 
            new CryptoPP::HashFilter(hash, 
                new CryptoPP::HexEncoder(
                    new CryptoPP::StringSink(digest), false // без пробелов
                )
            )
        );

        std::cout << "Хэш файла \"" << filename << "\": " << digest << std::endl;
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Ошибка Crypto++: " << e.what() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
    }
}

int main() {
    std::string filename;
    std::cout << "Введите путь к файлу: ";
    std::getline(std::cin, filename);

    HashFile(filename);

    return 0;
}
