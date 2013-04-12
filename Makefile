all: 
	gcc -lpcap -lgcrypt auth.c main.c -o 8021xd

clean:
	rm -rf 8021xd
