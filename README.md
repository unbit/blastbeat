The BlastBeat server
=========

BlastBeat is an high-performance HTTP/HTTPS proxy for new generation web apps (websockets, comet...).

It seats on front of your apps and will forward requests to them via a simple ZeroMQ protocol.

Each request will generate a ZeroMQ multipart message for your backends.

The message is composed of 3 parts: session id, message type, message body

'session id' identify a specific connection, a session id (once created by BlastBeat) is always mapped to
the same backend node.

'message type' identify the kind of the message. This is the list of currently defined message types:

* headers (request/response contains HTTP headers as a raw format)

* uwsgi (request/response contains HTTP headers encoded in uwsgi format)

* body (request/response contains raw body)

* chunk (response will encode the message in a HTTP chunk, REMEMBER: set the correct Transfer-Encoding in your
header) 

* end (request/response close the connection, REMEMBER: BlastBeat supports persistent connections !!!)

* websocket (request/response contains a websocket message)

* ping (request, check for a backend availability)

* pong (response, confirm a backend presence)


## building it

you need openssl,zeromq and libev development headers:

apt-get build-essential install libssl-dev libev-dev libzmq-dev

should be enough

run make to build the blastbeat daemon

## configure it

you need a .ini config file specifying the address:port to bind the server to, the zmq router address and a series of
allowed virtualhosts

```ini
[blastbeat]
bind = 0.0.0.0:8080
zmq = tcp://0.0.0.0:5000

[blastbeat:localhost:8000]
node = foobar1
```

run the server with:

./blastbeat yourfile.ini

The blastbeat server will start receiving HTTP request to the 8080 port and will forward them to a backend node
connected to the zmq router on port 5000.

## backend nodes

Backend nodes talk will blastbeat via a zmq dealer socket. That socket has to set a valid identity based on the node name
expected by the virtualhost.

In the previous example we have the localhost:8000 virtualhost expecting a single backend node with an identity of 'foobar1'

Identity is a form of authorization for allowing ISPs to host a single blastbeat server for their customers.

A simple python backend will be:

```python
import zmq

context = zmq.Context()
# create the dealer socket
socket = context.socket(zmq.DEALER)
# authorize it setting the identity
socket.setsockopt(zmq.IDENTITY, 'foobar1')
# connect to blastbeat
socket.connect('tcp://0.0.0.0:5000')

# start receiving messages
while True:
    sid, msg_type, msg_body = socket.recv_multipart()
    print 'received a message of type %s' % msg_type
```

## WebSockets

WebSocket requests are automagically managed by BlastBeat. You do not need to manage the handshake, as soon as BlastBeat
has completed the connection, you will start receiving messages of type 'websocket'

## using the sid (for concurrency)

The sid (the first part of blastbeat zeromq messages) is a binary value of variable size. The developer should not 
try to parse it, instead he should use it as the 'key' for a pool of threads/coroutine/greenthreads/whateveryouwant.

This is an example (using gevent and gevent-zeromq) of high-concurrency scenario:

A  main greenlet will receive blastbeat messages, for each new sid it find, a new greenlet will be created waiting on a queue
for messages.


```python
from gevent_zeromq import zmq
import gevent
from gevent.queue import Queue

context = zmq.Context()
# create the dealer socket
socket = context.socket(zmq.DEALER)
# authorize it setting the identity
socket.setsockopt(zmq.IDENTITY, 'foobar1')
# connect to blastbeat
socket.connect('tcp://0.0.0.0:5000')

# our sessions dictionary
sessions = {}

def worker(sid, socket, q):
    # wait for messages forwarded by the consumer
    while True:
        msg_type, msg_body = q.get() 
        print "received a message of type", msg_type
    
def consumer():
    while True:
        # receive a blastbeat message
        sid, msg_type, msg_body = socket.recv_multipart()
        # if a session for that sid is not available create it
        if not sid in sessions:
            # create a queue
            q = Queue()
            # spawn a greenlet fro the new client
            sessions[sid] = {'queue': q, 'thread': gevent.spawn(worker, sid, socket, q)}
    
       current_session = sessions[sid]
       current_session['queue'].put((msg_type, msg_body))

# start the consumer greenlet
main_loop = gevent.spawn(consumer)
gevent.joinall([main_loop])
```

## ping/pong

ping requests (and pong responses) have no sid associated. You have to simply respond to a ping request as soon as you receive it.

So your consumer will be (very probably) something like that:

```python
while True:
        # receive a blastbeat message
        sid, msg_type, msg_body = socket.recv_multipart()
        if msg_type == 'ping':
            zmq.send(sid, zmq.SNDMORE)
            zmq.send('pong', zmq.SNDMORE)
            zmq.send('')
            continue
```

ping/pong subsystem is used for nodes/backends healthchecks. If you do not respond to ping, your node will stop receiving requests pretty soon.

## uwsgi

by default the HTTP headers of a request are convert to a WSGI/PSGI/Rack-compliant dictionary encoded in the uwsgi format.
That choice should allow easy integration with already existing apps.

You can convert a uwsgi packet to a dictionary pretty easily:

```python
import struct
def uwsgi_to_dict(msg):
    (ulen, ) = struct.unpack('<H', msg[1:3])
    pos = 4
    env = {}
    while pos < ulen:
        (klen,) = struct.unpack('<H', msg[pos:pos+2])
        k = msg[pos+2:pos+2+klen]
        pos += 2+klen
        (vlen,) = struct.unpack('<H', msg[pos:pos+2])
        v = msg[pos+2:pos+2+vlen]
        pos += 2+vlen
        env[k] = v
    return env
```

## chunk

If you need to abuse chunked encoding for your applications, remember to set the Transfer-Encoding header:

```python

headers = '\r\n'.join(['HTTP/1.1 200 OK', 'Content-Type: text/html','Transfer-Encoding: chunked']) + '\r\n\r\n'
socket.send(sid, zmq.SNDMORE)
socket.send('headers', zmq.SNDMORE)
socket.send(headers)
for i in range(1,100):
    socket.send(sid, zmq.SNDMORE)
    socket.send('chunk', zmq.SNDMORE)
    socket.send('i am the number %d<br/>' % i)
```

to end a chunked response just send an empty chunk

```python
socket.send(sid, zmq.SNDMORE)
socket.send('chunk', zmq.SNDMORE)
socket.send('')
```
