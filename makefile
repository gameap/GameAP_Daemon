CC=g++
CFLAGS=-lmine -c -Wall -std=c++11

all: server

server: functions.o server.o daemon.o
	#~ $(CC) functions.o server.o -o server -lm -lboost_regex -lboost_thread -lboost_system
	$(CC) functions.o crypt.o daemon.o -o daemon -static /usr/lib/x86_64-linux-gnu/libboost_system.a /usr/lib/x86_64-linux-gnu/libboost_thread.a /usr/lib/x86_64-linux-gnu/libboost_regex.a -pthread -L -lm -lboost_regex -lboost_thread -lboost_system -lcrypto -lcryptopp -ljsoncpp
#~ 	$(CC) functions.o crypt.o daemon.o -o daemon -static /usr/lib/i386-linux-gnu/libboost_system.a /usr/lib/i386-linux-gnu/libboost_thread.a /usr/lib/i386-linux-gnu/libboost_regex.a -pthread -L -lm -lboost_regex -lboost_thread -lboost_system -lcrypto -lcryptopp -ljsoncpp
	make clean
	
functions.o:
	$(CC) $(CFLAGS) functions.cpp -lm -lboost_regex -lboost_thread -lboost_system
	
server.o:
	#~ $(CC) $(CFLAGS) server.cpp -lm -lboost_regex -lboost_thread -lboost_system
	
daemon.o: crypt.o 
	 $(CC) $(CFLAGS) daemon.cpp -pthread -L -lm -lboost_regex -lboost_thread -lboost_system -lcrypto -lcryptopp -ljsoncpp

crypt.o:
	 $(CC) $(CFLAGS) crypt.cpp -lcrypto -lcryptopp -ljsoncpp
 
clean:
	rm -rf *.o
