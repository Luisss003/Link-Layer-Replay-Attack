all: main.c packet_reading.c
	gcc main.c packet_reading.c -lpcap -ldumbnet -o assign4

clean:
	$(RM) assign4
