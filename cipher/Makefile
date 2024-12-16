

TARGET = file_encrypt_decrypt

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
LDFLAGS = -lcryptopp

SRC = file_encrypt_decrypt.cpp

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)

# Фиктивные цели
.PHONY: clean
