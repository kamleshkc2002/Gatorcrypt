##define the flags and setting it to warn all.
##use the GCC compiler to compile the targets
CFLAGS=-Wall -g
gatorcrypt gatordec: gatorcrypt.c gatordec.c utils.c
	gcc -o gatorcrypt gatorcrypt.c utils.c `libgcrypt-config --cflags --libs` -lm
	gcc -o gatordec gatordec.c  utils.c `libgcrypt-config --cflags --libs` -lm
    
