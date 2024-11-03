all: task2_make

task0_make:
	gcc -m32 -o loader task2.c

task2_make:
	nasm -f elf32 -o start.o start.s
	nasm -f elf32 -o startup.o startup.s
	gcc -m32 -c task2.c -o loader.o
	ld -o loader loader.o startup.o start.o -L/usr/lib32 -lc -T linking_script -dynamic-linker /lib/ld-linux.so.2

.PHONY: clean
clean:
	rm -f *.o loader