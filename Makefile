all: read_class read_dex

CFLAGS := -std=c++11 -g

read_class : read_class.cpp utils.h java_class.h java_class_namemap.h Makefile
	g++ -o $@ $< $(CFLAGS)

read_dex: read_dex.cpp utils.h Makefile dex.h dex_namemap.h
	g++ -o $@ $< $(CFLAGS)

clean:
	rm -rf read_class read_dex *.o
