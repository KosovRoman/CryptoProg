# Компилятор и флаги
CXX = g++
CXXFLAGS = -std=c++11 -I/usr/include/cryptopp

# Целевые файлы
TARGET = hash
SRC = hash.cpp
OBJ = hash.o

# Сборка программы
all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) -o $(TARGET) $(OBJ) -lcryptopp

$(OBJ): $(SRC)
	$(CXX) $(CXXFLAGS) -c $(SRC)

# Удаление скомпилированных файлов
clean:
	rm -f $(OBJ) $(TARGET)

