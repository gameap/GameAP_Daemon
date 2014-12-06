CC=g++
CFLAGS=-c -Wall -std=c++11

all: server

server: functions.o server.o daemon.o
	#~ $(CC) functions.o server.o -o server -lm -lboost_regex -lboost_thread -lboost_system
	$(CC) config.o log.o crypt.o daemon.o -o daemon -pthread -L -lm -lboost_regex -lboost_thread -lboost_system -lcrypto -lcryptopp -ljsoncpp
	make clean
	
functions.o:
	$(CC) $(CFLAGS) functions.cpp -lm -lboost_regex -lboost_thread -lboost_system
	
config.o:
	$(CC) $(CFLAGS) config/config.cpp
	
server.o:
	#~ $(CC) $(CFLAGS) server.cpp -lm -lboost_regex -lboost_thread -lboost_system
	
daemon.o: crypt.o config/config.o
	 $(CC) $(CFLAGS) daemon.cpp -pthread -L -lm -lboost_regex -lboost_thread -lboost_system -lcrypto -lcryptopp -ljsoncpp

crypt.o:
	 $(CC) $(CFLAGS) crypt.cpp -lcrypto -lcryptopp -ljsoncpp
	 
config/config.o: config/log.o
	$(CC) $(CFLAGS) config/config.cpp
	 
config/log.o:
	$(CC) $(CFLAGS) config/log.cpp
	 
clean:
	rm -rf *.o
