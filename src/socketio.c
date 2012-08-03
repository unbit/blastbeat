#include "../blastbeat.h"

/*

socket.io management

/socket.io/1/ -> send handshake response using the bb sid, mark the sid as persistent

/socket.io/1/xhr-polling/<sid> -> recover the session id and move the current request to it
parse the body and generate the socket.io/type message

/socket.io/1/websocket/<sid> -> recover the session id and move the current request to it
parse each websocket message twice (one for websocket and one for socket.io format) and generate
the socket.io/type message

*/


int bb_manage_socketio(struct bb_session_request *bbsr) {
	return -1;
}
