all: main.c packet_reading.c pkt_trans.c cfg_processing.c
	gcc main.c packet_reading.c pkt_trans.c cfg_processing.c -lpcap -ldumbnet -o attgen 

clean:
	$(RM) attgen
