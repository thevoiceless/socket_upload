POLARSSL = -lpolarssl -I/home/riley/Computer/polarssl-1.2.8/include/polarssl/

CLASSES = SocketUpload.class
OBJECTS = socket_upload_ssl.o
JAVAS = SocketUpload.java
CPPS = socket_upload_ssl.cpp
EXES = socket_upload_ssl

all: java cpp $(CLASSES) $(OBJECTS)

java: $(JAVAS)
	javac $(JAVAS)

cpp: objects $(OBJECTS)
	g++ $(OBJECTS) -o socket_upload_ssl $(POLARSSL)

objects: $(CPPS)
	g++ -c $(CPPS)

clean:
	-rm $(CLASSES)
	-rm $(OBJECTS)
	-rm $(EXES)
