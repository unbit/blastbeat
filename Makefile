all:
	gcc -g -O2 -Wall -Wno-strict-aliasing -o blastbeat src/main.c src/config.c src/zmq.c src/http.c src/ssl.c src/spdy.c src/uwsgi.c src/websocket.c src/sessions_ht.c src/writequeue.c http-parser/http_parser.c -lzmq -lssl -lcrypto -lev -lz -luuid
