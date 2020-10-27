all: elfan

elfan: main.c elfhread.c
	gcc -o elfan elfhread.c main.c

debug: main.c elfhread.c
	gcc -g -o elfan elfhread.c main.c

clean:
	rm elfan