# Compiler and linker settings
CXX = g++
CXXFLAGS = -Wall -std=c++2a
LDLIBS = -lpcap

LOGIN = xgonce00
NAME = ipk-sniffer
# Source file and output file
SRC = $(NAME).cpp args.cpp sniff.cpp
HEADERS = args.h sniff.h
EXEC = $(NAME)

.PHONY: all clean
# Default target
all: $(EXEC) 

# Compile and link the program
$(EXEC): $(SRC:.cpp=.o)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDLIBS)
	
# Compile all source files
%.o: %.cpp %.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

pack:
	zip $(LOGIN).zip $(SRC) $(HEADERS) Makefile README.md CHANGELOG.md test/test.py

# Clean the build files
clean:
	rm -f $(EXEC) $(SRC:.cpp=.o)
