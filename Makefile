all:
	gcc -g -o blastbeat src/main.c src/config.c src/http.c src/uwsgi.c src/websocket.c src/sessions_ht.c src/writequeue.c http-parser/http_parser.c -lzmq -lssl -lcrypto -lev
