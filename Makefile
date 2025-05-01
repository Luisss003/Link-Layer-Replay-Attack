all: main.c packet_reading.c pkt_trans.c cfg_processing.c packet_sniffing.c
	gcc main.c packet_reading.c pkt_trans.c cfg_processing.c packet_sniffing.c -lpcap -ldumbnet -o attgen 

clean:
	$(RM) attgen
