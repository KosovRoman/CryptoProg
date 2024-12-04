#include <cryptlib.h>
#include <sha.h>
#include <hex.h>
#include <files.h>
#include <filters.h>
#include <iostream>
#include <string>

using namespace CryptoPP;

void hashFile(const std::string &filename) {
    SHA256 hash;
    FileSource file(filename.c_str(), true,
                    new HashFilter(hash, new HexEncoder(new FileSink(std::cout))));
    std::cout << std::endl;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <filename>" << std::endl;
        return 1;
    }

    hashFile(argv[1]);
    return 0;
}

