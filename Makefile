all: read_class

read_class : read_class.cpp
	g++ -o $@ $< -std=c++11
