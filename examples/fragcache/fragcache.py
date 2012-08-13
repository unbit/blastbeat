"""
The Fragment cache allows you to store 'fragment' of datas in the blastbeat cache
for fast usage during the generation of a response.

If you have parts of your responses that do not change too often you can store them
directly on blastbeat avoiding to transfer them over and over again.

It is important to remember that whenever BlastBeat is rebooted, the cache is cleared.
The dealer should re-fill the fragment cache whenever a 'spawn' message is received.

To store a fragment in the cache use 'fragcache', to ask BlastBeat to send a fragment to
the client use the 'frag' message type.

If BlastBeat does not find a requested 'fragment' it will skip over the next chunk/body

TODO: being async, you are not able to know if a fragment store failed. To avoid such a
problem, a 'nomem' message should be implemented, informing the dealer it will not be able to
store datas in the cache. Problems: how much free memory should trigger a 'okmem' to inform
the dealer to start again caching things...
"""

import zmq

context = zmq.Context()
# create the dealer socket
socket = context.socket(zmq.DEALER)
# authorize it setting the identity
socket.setsockopt(zmq.IDENTITY, 'FOOBAR1')
# connect to blastbeat
socket.connect('tcp://192.168.173.5:5000')

# fill the fragment cache with some HTML...

header = """
<html>
  <body>
    <h1>I am The Header</h1>
    <div id="content">
"""

footer = """
    </div>
    <hr/>
    </h3>i am the footer...</h3>
  </body>
</html>
"""

# became True as soon as we write fragments in the cache
filled = False

# start receiving messages
while True:
    sid, msg_type, msg_body = socket.recv_multipart()
    # respond with pong
    if msg_type == 'ping':
        socket.send_multipart([sid, 'pong', ''])
    elif msg_type == 'spawn':
        print 'BlastBeat respawned, re-fill the fragment cache'
        filled = False
    elif msg_type == 'uwsgi':
        # here we fill the cache
        if not filled:
            socket.send_multipart([sid, 'fragcache', 'header_fragment\r\n%s' % header])
            socket.send_multipart([sid, 'fragcache', 'footer_fragment\r\n%s' % footer])
            filled = True

        socket.send_multipart([sid, 'headers', "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"])

        socket.send_multipart([sid, 'frag', 'header_fragment'])

        socket.send_multipart([sid, 'body', 'I am The Body<br/>'])
        socket.send_multipart([sid, 'body', 'I am The Body<br/>'])
        socket.send_multipart([sid, 'body', 'I am The Body<br/>'])
        socket.send_multipart([sid, 'body', 'I am The Body<br/>'])
        socket.send_multipart([sid, 'body', 'I am The Body<br/>'])
        socket.send_multipart([sid, 'body', 'I am The Body<br/>'])
        socket.send_multipart([sid, 'body', 'I am The Body<br/>'])
        socket.send_multipart([sid, 'body', 'I am The Body<br/>'])
        socket.send_multipart([sid, 'body', 'I am The Body<br/>'])

        socket.send_multipart([sid, 'frag', 'footer_fragment'])

        socket.send_multipart([sid, 'end', ''])
