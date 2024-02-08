CC = g++
CXXFLAGS = -Wall -Wextra -I/usr/include/openssl -I./include
LDFLAGS = -L/usr/lib -lssl -lcurl -lcrypto

TARGET = trans
SOURCES = main.cpp
OBJECTS = $(SOURCES:.cpp=.o)

$(TARGET) : $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $(TARGET)

%.o: %.cpp
	$(CC) -c $< $(CXXFLAGS) -o $@

.PHONY: clean
clean:
	rm -f $(OBJECTS) $(TARGET)
