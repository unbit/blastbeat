all:
	gcc -g -o blastbeat src/main.c src/config.c src/http.c src/websocket.c http-parser/http_parser.c -lzmq -lssl -lcrypto -lev
