CFLAGS=-g -O2 -Wall -Wno-strict-aliasing
LIBS=-lzmq -lssl -lcrypto -lev -lz -luuid

OBJ = src/main.o src/config.o src/zmq.o src/http.o src/ssl.o src/spdy.o src/uwsgi.o src/websocket.o src/sessions_ht.o src/writequeue.o src/groups.o src/socketio.o http-parser/http_parser.o


all: $(OBJ)
	$(CC) $(CFLAGS) -o blastbeat $(OBJ) $(LIBS)

clean:
	rm -f src/*.o http-parser/*.o

$(OBJ): blastbeat.h
