CC = g++
CFLAGS = -g -Wall
OBJS = main.o
TARGET = capture_tcp 

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) -lpcap
	rm *.o

main.o: hdr.h main.cpp

clean:
	rm -rf *.o $(TARGET)
