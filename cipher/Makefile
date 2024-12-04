# Имя программы
TARGET = cipher

# Компилятор и флаги
CXX = g++
CXXFLAGS = -std=c++11 -I/usr/include/cryptopp
LDFLAGS = -lcryptopp

# Исходные файлы
SRC = cipher.cpp

# Правила сборки
all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)

