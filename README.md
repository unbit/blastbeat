The BlastBeat server
=========

BlastBeat is an high-performance HTTP/HTTPS/SPDY proxy for new generation web apps (websockets, socket.io, push, comet...).

It seats on front of your apps and will forward requests to them via a simple ZeroMQ protocol.

Each request will generate a ZeroMQ multipart message for your backends.

The message is composed of 3 parts: session id, message type, message body

'session id' identify a specific connection in HTTP mode or a specific stream in SPDY mode, a session id (once created by BlastBeat) is always mapped to
the same backend node.

'message type' identify the kind of the message. This is the list of currently defined message types:

* **headers** (response contains HTTP headers in raw format, Example: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")

* **uwsgi** (request/response contains HTTP headers encoded in uwsgi format)

* **body** (request/response contains raw body)

* **chunk** (response will encode the message in a HTTP chunk, REMEMBER: set the correct Transfer-Encoding in your
header. SPDY sessions do not support chunked messages) 

* **end** (request/response close the connection of HTTP requests and the stream of a SPDY one, REMEMBER: BlastBeat supports HTTP persistent connections !!!)

* **websocket** (request/response contains a websocket message)

* **ping** (request, check for a backend availability)

* **pong** (response, confirm a backend presence)

* **retry** (response, ask BlastBeat to make the same request to another node REMEMBER: there is a maximum of 'retry' messages per-session)

* **msg** (internal, route a message to a session or a group)

* **join** (join a BlastBeat group, it is required for sending messages to peers in the same group)

* **leave** (leave a BlastBeat group)

* **push** (SPDY push service, works like 'headers', see below)

* **cache** (place an HTTP response in the cache, see below)

* **socket.io/event** (receive/send a socket.io event)

* **socket.io/msg** (receive/send a socket.io message)

* **socket.io/json** (receive/send a socket.io JSON-encoded object)

* **socket.io/end** (gracefully destroy a socket.io session)

* **spawn** (sent from BlastBeat to dealers whenever it spawn)

* **pipe** (enable pipe mode. documentation coming soon)

Commands in development/study/analysis

* **move** (move the session to another node)

* **timeout** (auto-close session after inactivity)

* **timer** (create a recurring timer)

* **oneshot** (create a oneshot timer)

* **goaway** (SPDY-friendly connection interruption)

* **auth** (stronger authentication for dealers)

* **fragcache** (store a fragment in the cache)
             
* **frag** (send a fragment to the client)

* **bandwidth** (limit bandwidth for the current connection)

* **ssl** (send key, cert and diffie-helman to enable ssl/tls via Server Name Indication (SNI) )

* **sslverify** (if in SNI mode, force client ssl authentication using the supplied CA)

feel free to propose your ideas...

Some message type can be 'routed' using a special syntax for the 'type' part:

group:type -> will route the message to a BlastBeat group

@sid:type -> will route the message to an active session

Routing has a different meaning based on the type, for example, routing a websocket message
will send websocket packets to the related clients, while routing a msg will generate another zeromq
message for the relevant dealer. Message types not supporting routing will simply ignore the part before the last colon.

## building it

you need openssl,zeromq,zlib and libev development headers:

apt-get build-essential install libssl-dev libev-dev libzmq-dev libz-dev

should be enough for a Debian/Ubuntu system

while

brew install libev zmq ossp-uuid

should be enough for OSX

run make to build the blastbeat daemon

## configure it

you need a .ini config file specifying the address:port to bind the server to, the zmq router address and a series of
allowed virtualhosts

```ini
[blastbeat]
bind = 0.0.0.0:8080
zmq = tcp://0.0.0.0:5000

[blastbeat:localhost:8080]
node = foobar1
```

run the server with:

./blastbeat yourfile.ini

The blastbeat server will start receiving HTTP request to the 8080 port and will forward them to a backend node
connected to the zmq router on port 5000.


You can bind specific virtualhost to specific address (as required by https) including bind/bind-ssl options in the virtualhost config

```ini
[blastbeat]
bind = 0.0.0.0:8080
zmq = tcp://0.0.0.0:5000

[blastbeat:localhost:8080]
node = foobar1

[blastbeat:secure.local]
node = foobar2
bind = 0.0.0.0:8181
```

to use HTTPS just specify bind-ssl, certificate and key options:

```ini
[blastbeat]
bind = 0.0.0.0:8080
zmq = tcp://0.0.0.0:5000

[blastbeat:localhost:8080]
node = foobar1

[blastbeat:secure.local]
node = foobar2
bind-ssl = 0.0.0.0:443
certificate = foo.pem
key = foo.key
```

To generate keys/certificates for testing (self-signed) just do that:

```
openssl genrsa -out foobar.key 2048
openssl req -new -key foobar.key -out foobar.csr
openssl x509 -req -days 365 -in foobar.csr -signkey foobar.key -out foobar.crt
```

that will result in foobar.key and foobar.crt

You can avoid allocating one ip for each https virtualhost using SNI (Server Name Identification). This is supported
by all modern browsers. Just use the same bind-ssl directive for all of the virtualhost sharing the same address

## backend nodes

Backend nodes talk will blastbeat via a zmq dealer socket. That socket has to set a valid identity based on the node name
expected by the virtualhost.

In the previous example we have the localhost:8080 virtualhost expecting a single backend node with an identity of 'foobar1'

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

You can have all of the backends you need for each virtualhost. Just add multiple 'node' entries

```ini
[blastbeat]
bind = 0.0.0.0:8080
zmq = tcp://0.0.0.0:5000

[blastbeat:localhost:8080]
node = foobar1

[blastbeat:secure.local]
node = foobar2
node = foobar3
node = foobar4
node = foobar5
bind-ssl = 0.0.0.0:443
certificate = foo.pem
key = foo.key
```

Each node will be load-balanced using a "least connection" algorithm, dead/available nodes are detected via the ping/pong susbsystem

Load balancing for HTTP/HTTPS requests is per-connection, while in SPDY mode is per-stream, so a single SPDY session could be load-balanced to
multiple nodes automagically

## WebSockets

WebSocket requests are automagically managed by BlastBeat. You do not need to manage the handshake, as soon as BlastBeat
has completed the connection, you will start receiving messages of type 'websocket'

An echo service would be something like that:

```python
while True:
        # receive a blastbeat message
        sid, msg_type, msg_body = socket.recv_multipart()
        if msg_type == 'websocket':
            zmq.send(sid, zmq.SNDMORE)
            zmq.send('websocket', zmq.SNDMORE)
            zmq.send("received: %s" % msg_body)
            continue
```

Websockets over https are supported, just use the wss:// form in your javascript code

## SPDY (v2)

If the client supports SPDY 2 protocol, it will be preferred over HTTPS.

Each stream is mapped to a different sid.

To end a stream just send a 'end' message or an empty 'body' message.

## SPDY push

You can push resources with the 'push' message type.

Whenever you send a 'push' message, a new stream is created and will be the active one til a 'end' command is issued.

A 'push' message is like the 'headers' one. Just remember to set the Url: header, reporting the full url of the resource.

```python

# send the headers for the main request
zmq.send(sid, zmq.SNDMORE)
zmq.send('headers', zmq.SNDMORE)
zmq.send("HTTP/1.1 200 Ok\r\nContent-Type: text/html\r\n\r\n")

# push a new resource
zmq.send(sid, zmq.SNDMORE)
zmq.send('push', zmq.SNDMORE)
zmq.send("HTTP/1.1 200 Ok\r\nContent-Type: text/javascript\r\nUrl: https://foobar.it/test1.js\r\n\r\n")

# push its body
zmq.send(sid, zmq.SNDMORE)
zmq.send('body', zmq.SNDMORE)
zmq.send("alert('hello');")

# end the stream
zmq.send(sid, zmq.SNDMORE)
zmq.send('end', zmq.SNDMORE)
zmq.send('')

# we are now (again) in the main request
# send its body
zmq.send(sid, zmq.SNDMORE)
zmq.send('body', zmq.SNDMORE)
zmq.send('<script type="text/javascript" src="/test1.js"></script>')

# ...and close the main stream
zmq.send(sid, zmq.SNDMORE)
zmq.send('end', zmq.SNDMORE)
zmq.send('')
```

## socket.io

socket.io is a javascript library emulating sockets into the browser abstracting the underlying subsystem.

BlastBeat supports socket.io over websockets and via xhr-polling, that should allows support for
all of the major browsers out there.

Handshaking, connection management, heartbeats and all of the internals of socket.io are managed by BlastBeat,
you only need to worry about the logic of your app.

Each socket.io connection is mapped to a BlastBeat session, whenever a peer send a message you will receive one of
this three message types (based on the content of the socket.io message)

socket.io/event (for a socket.io event)

socket.io/msg (for a socket.io raw message)

socket.io/json (for a socket.io json object)

you can use the same three message type for sending socket.io messages from teh server (dealer) to clients.

An additional message type 'socket.io/end' allows you to gracefully close socket.io sessions

An example receiving a json message and responding with an event (remember socket.io events are json object with
at least 'name' and 'args' attributes)

```python
if msg_type == 'socket.io/json':
        socket.send_multipart([sid, 'socket.io/event', '{"name":"news","args":"JSON"}'])
```

## using the sid (for concurrency)

The sid (the first part of blastbeat zeromq messages) is a binary value of variable size (normally it is a 128bit UUID). The developer should not 
try to parse it, instead use it as the 'key' for a pool of threads/coroutine/greenthreads/whateveryouwant.
The sid should be able to identify a specific request even on a pool of servers (that is why UUID is used)

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

ping requests (and pong responses) have no real sid associated. You have to simply respond to a ping request as soon as you receive it.

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

## Caching

BlastBeat can create an in-memory cache for each configured virtualhost.

Dealers can write HTTP response in that memory and BlastBeat will directly serve response from there (if available).

Caching is disabled by default, you have to enable it in every virtualhost you need specifying its maximum size

```ini
[blastbeat:localhost]
node = application001
cache = 17
```

This will create a cache area of 17 Megabytes.

Dealers wanting to store datas in the cache, need to use the 'cache' message type:

```python
socket.send(sid, zmq.SNDMORE)
socket.send('cache', zmq.SNDMORE)
socket.send('/foobar001\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<H1>Hello World</h1>')
```

The 'cache' message body is composed by two areas (delimited by \r\n). The first 'line' has this syntax:

```
<key> [expires] [flags]
```

key is the uri BlastBeat will use for the cache item, expires is the number of seconds after the cache item is destroyed.

Flags currently can be 0 or 1, with 1 meaning 'overwrite/update' the cache item (without that, update requests will be discarded)

To remove an item from the cache just pass an empty HTTP response:

```python
socket.send(sid, zmq.SNDMORE)
socket.send('cache', zmq.SNDMORE)
socket.send('/foobar001\r\n')
```

## Bandwidth

You can limit the amount of bandwidth used by each virtualhost

```ini
[blastbeat]
bind = 0.0.0.0:80
zmq = tcp://192.168.173.5:5000

[blastbeat:unbit.it]
; limit to 100 kbit/s
bandwidth = 100

[blastbeat:uwsgi.it]
; limit to 1MBit/s
bandwidth = 1000
```

The algorithm used is the 'token bucket' with a resolution of 30ms.

Albeit blastbeat is not intended for big-files serving, you can use it as a streaming (audio/video) server
so limiting bandwidth could be a good solution for QoS

Take in account limiting bandwidth could mean increasing a lot (in terms of memory) the writequeue required
for non blocking writes. By default you can enqueue upto 8Megabytes of datas, you can increase (or decrease) that value
with the 'writequeue-buffer' option

```ini
[blastbeat]
bind = 0.0.0.0:80
zmq = tcp://192.168.173.5:5000
; 10 mbytes per-connection
writequeue-buffer = 10485760
```

## Memory and Security

New web technologies introduce a new set of security problems, most of them are related to resource usage.

You can limit the total amount of memory used by BlastBeat with the 'memory' option

```ini
[blastbeat]
bind = 0.0.0.0:80
zmq = tcp://192.168.173.5:5000
; do not use more than 2GB of memory
memory = 2000
```

Or you can limit the number of sessions, both per-server and per-virtualhost

```ini
[blastbeat]
bind = 0.0.0.0:80
zmq = tcp://192.168.173.5:5000
; do not use more than 2GB of memory
memory = 2000
; max 100 sessions
sessions = 100

[blastbeat:unbit.it]
; max 10 session for this virtualhost
sessions = 10
```


## Ruby EventMachine example

```ruby
require 'rubygems'
require 'em-zeromq'

# here we initialize the eventmachine-fiendly ZeroMQ context
ctx = EM::ZeroMQ::Context.new(1)

# this will be invoiked whenver a zeromq event is triggered
class EMTestPullHandler

        # convert a uwsgi packet to a ruby hash (in Rack format)
        def uwsgi_to_hash(pkt)
                ulen, = pkt[1,2].unpack('v')
                pos = 4
                h = Hash.new
                while pos < ulen
                        klen, = pkt[pos,2].unpack('v')
                        k = pkt[pos+2, klen]
                        pos += 2+klen
                        vlen, = pkt[pos,2].unpack('v')
                        v = pkt[pos+2, vlen]
                        pos += 2+vlen
                        h[k] = v
                end
                h
        end

        # this event will be triggered whenever a ZeroMQ-BlastBeat message is available
        def on_readable(socket, parts)
                # get the BlastBeat sid
                sid = parts[0].copy_out_string
                # get the BlastBeat command
                command = parts[1].copy_out_string
                # get the BlastBeat body
                body = parts[2].copy_out_string

                # is it a ping command ?
                if command == 'ping'
                        socket.send_msg(sid, 'pong', '')
                # a uwsgi packet ?
                elsif command == 'uwsgi'
                        # parse the packet into a Rack hash
                        env = uwsgi_to_hash(body)
                        # generate HTTP headers
                        headers = []
                        headers << "#{env['SERVER_PROTOCOL']} 200 OK"
                        headers << "Content-Type: text/html"
                        headers << "Server: tremolo.rb"

                        # send headers
                        socket.send_msg(sid, 'headers', headers.join("\r\n") + "\r\n\r\n")
                        # send body
                        socket.send_msg(sid, 'body', '<h1>Hello World</h1>')
                        # send body (again and again and again)
                        socket.send_msg(sid, 'body', '<h2>Done !!!</h2>')
                        socket.send_msg(sid, 'body', '<h3>Done !!!</h3>')
                        socket.send_msg(sid, 'body', '<h4>Done !!!</h4>')
                        # close the session
                        socket.send_msg(sid, 'end', '')

                # a websocket message ? (echo it !!!)
                elsif command == 'websocket'
                        socket.send_msg(sid, 'websocket', body)
                end
        end
end

# the main eventmachine loop
EM.run do
        dealer = ctx.socket(ZMQ::DEALER, EMTestPullHandler.new)
        # set the identity
        dealer.setsockopt(ZMQ::IDENTITY, 'FOOBAR1')
        # connect to BlastBeat
        dealer.connect('tcp://192.168.173.5:5000')
end

```

## Status/Issues

* No logging system, all messages go to stdout/stderr


## TODO

* uWSGI Emperor support

* graceful reloads (or dynamic config ?)

* Multiple zmq router support

## Support

you can ask for help in the official mailing-list

http://lists.unbit.it/cgi-bin/mailman/listinfo/blastbeat

## Twitter

@unbit

## IRC (freenode)

 \#uwsgi