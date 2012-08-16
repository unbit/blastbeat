Building a VideoChat with Websockets and BlastBeat pipes
=========

This example/tutorial will show you how to use the 'pipe' system of BlastBeat to forward
big messages (like video frames) to peers/groups with efficiency and speed.

Video frames and control messages (like joining channel or sending text messages) will be managed by two different
Websocket connections.

Supposing our BlastBeat server is on 127.0.0.1:8080 we will use ws://127.0.0.1:8080/control for control messages (they will be json
objects) and ws://127.0.0.1:8080/data/-cookie- for video frames. -cookie- will be a code returned by the control channel
to authorize the user to send/receive videoframes.