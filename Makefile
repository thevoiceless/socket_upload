POLARSSL = -lpolarssl -I/home/riley/Computer/polarssl-1.2.8/include/polarssl/

OBJS = socket_upload_ssl.o
CPPS = socket_upload_ssl.cpp
EXES = socket_upload_ssl

all: objects $(OBJS)
	g++ $(OBJS) -o socket_upload_ssl $(POLARSSL)

objects: $(CPPS)
	g++ -c $(CPPS)

clean:
	rm $(OBJS)
	rm $(EXES)
