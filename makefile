all: send-arp

send-arp: main.o send-arp.o
	gcc -o send-arp main.o send-arp.o -lpcap

main.o: main.c
	gcc -c -o main.o main.c

send-arp.o: send-arp.c
	gcc -c -o send-arp.o send-arp.c

clean:
	rm -f send-arp
	rm -f *.o