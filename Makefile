CC = gcc
CFLAGS = -g -Wall -Wextra -lpcap -lm
TARGET = ex1

all : $(TARGET)

ex1 : ex1.o
	$(CC) -o $@ $^ $(CFLAGS)
	rm $^

clean :
	rm $(TARGET)