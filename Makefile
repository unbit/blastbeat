CFLAGS+=-g -O2 -Wall -Wno-strict-aliasing
LIBS+=-lzmq -lssl -lcrypto -lev -lz -luuid

OBJ=src/main.o
OBJ+=src/utils.o
OBJ+=src/config.o
OBJ+=src/zmq.o
OBJ+=src/http.o
OBJ+=src/ssl.o
OBJ+=src/spdy.o
OBJ+=src/uwsgi.o
OBJ+=src/websocket.o
OBJ+=src/sessions_ht.o
OBJ+=src/writequeue.o
OBJ+=src/groups.o
OBJ+=src/socketio.o
OBJ+=src/cache.o
OBJ+=src/pipe.o
OBJ+=src/memory.o
OBJ+=http-parser/http_parser.o


all: $(OBJ)
	$(CC) $(CFLAGS) -o blastbeat $(OBJ) $(LIBS)

clean:
	rm -f src/*.o http-parser/*.o

$(OBJ): blastbeat.h
