all: read_class read_dex

read_class : read_class.cpp utils.h java_class.h java_class_namemap.h
	g++ -o $@ $< -std=c++11

read_dex: read_dex.cpp utils.h
	g++ -o $@ $< -std=c++11