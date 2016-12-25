exe=gcc

OBJS1=main.c fill_packet.c pcap.c

all: myping 

myping: $(OBJS1)
	$(exe) $(OBJS1) -o $@ -lpcap

clean:
	rm -f myping

