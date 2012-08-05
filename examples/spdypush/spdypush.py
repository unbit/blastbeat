"""
An example of high-concurrency SPDY push service

this example shows how to push resources in a SPDY stream
Each stream is mapped to a Greenlet while a main consumer receives
blastbeat messages and forward them to the related Greenlet (keyed by the sid)

The SPDYStream class maps to a single SPDY stream
The BlastBeatConsumer class is the main Greenlet consuming blastbeat messages

The examples shows how to parse uwsgi packets via the uwsgi_to_dict() method

The examples shows a way to manage 'end' messages in gevent context:
- kill the greenlet
- delete the session from the sessions dictionary

Remember: the 'end' message could be related to a non-exisiting session (for various reason)

Note the 'gratuituous pong' on the beginning to pair the dealer as soon as possibile
with the blastbeat router

To run it just configure (at the end of the code) with the blastbeat zmq address and the node name

"""

# try importing official zmq green bindings
# or fallback to gevent_zeromq
try:
    import zmq.green as zmq
except ImportError:
    from gevent_zeromq import zmq

import gevent
from gevent.queue import Queue

import struct


class SPDYStream():

    # function for translating uwsgi packets to python dictionaries
    def uwsgi_to_dict(self,msg):
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


    def loop(self):
        while True:
            msg_type,msg_body = self.queue.get()
            # is it a new request/stream ?
            if msg_type == 'uwsgi':
                # transform the uwsgi packet in a python WSGI/CGI dictionary
                environ = self.uwsgi_to_dict(msg_body)

                # PUSHed resources must not be asked by the browser
                if environ['PATH_INFO'] in ('/js', '/js2'):
                    raise Exception('SPDY push is not working !!!')

                # generate response headers for the main SPDY stream
                headers = ['HTTP/1.1 200 OK']
                headers.append('Content-Type: text/html')
                headers.append('BlastBeat001: 001')
                headers.append('BlastBeat002: 002')
                headers.append('BlastBeat003: 003')
                # send headers
                self.consumer.socket.send_multipart([self.sid, 'headers', '\r\n'.join(headers)+'\r\n\r\n'])
                # send a bunch of bodies
		self.consumer.socket.send_multipart([self.sid, 'body', '<script src="/js"></script>'])
                self.consumer.socket.send_multipart([self.sid, 'body', '<script src="/js2"></script>'])

                # push a new stream (REMEMBER to set the Url header !!!)
                url = 'https://%s/js' % environ['HTTP_HOST']
                self.consumer.socket.send_multipart([self.sid, 'push', 'HTTP/1.1 200 OK\r\nContent-Type: text/javascript\r\nUrl: %s\r\n\r\n' % url])
                self.consumer.socket.send_multipart([self.sid, 'body', 'alert("PUSH IS WORKING...");'])
                self.consumer.socket.send_multipart([self.sid, 'end', ''])

                # push another stream (REMEMBER to set the Url header !!!)
                url = 'https://%s/js2' % environ['HTTP_HOST']
                self.consumer.socket.send_multipart([self.sid, 'push', 'HTTP/1.1 200 OK\r\nContent-Type: text/javascript\r\nUrl: %s\r\n\r\n' % url])
                self.consumer.socket.send_multipart([self.sid, 'body', 'alert("REALLY WELL");'])
                self.consumer.socket.send_multipart([self.sid, 'end', ''])

                # back to main stream
                self.consumer.socket.send_multipart([self.sid, 'body', '<h1>ready</h1>'])
                self.consumer.socket.send_multipart([self.sid, 'body', '<h2>ready</h2>'])
                self.consumer.socket.send_multipart([self.sid, 'body', '<h3>ready</h3>'])
                self.consumer.socket.send_multipart([self.sid, 'body', '<h4>ready</h4>'])
                self.consumer.socket.send_multipart([self.sid, 'body', '<h5>ready</h5>'])

                # end the main stream
                self.consumer.socket.send_multipart([self.sid, 'end', ''])
                

    def __init__(self, consumer, sid):
        self.consumer = consumer
        self.sid = sid
        self.queue = Queue()
        self.greenlet = gevent.spawn(self.loop)

# this is the consumer of blastbeat events
# whenever a new message is received it will
# be forwarded to the mapped greenlet
class BlastBeatConsumer():

    def __init__(self, blastbeat, nodename):
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.DEALER)
        self.socket.setsockopt(zmq.IDENTITY, nodename)
        self.socket.connect(blastbeat)
        self.sessions = {}

    def loop(self):
        while True:
            sid, msg_type, msg_body = self.socket.recv_multipart()
            # healthcheck
            if msg_type == 'ping':
                self.socket.send_multipart(['', 'pong', ''])
                continue
            # destroy a session
            # a session could be already dead
            # so wrap it into an exception
            if msg_type == 'end':
               try:
                   gevent.kill(self.sessions[sid].greenlet)
                   del(self.sessions[sid])
               except:
                   pass
    
            # enqueue the message to the mapped greenlet
            if sid not in self.sessions:
                self.sessions[sid] = SPDYStream(self, sid)
            self.sessions[sid].queue.put([msg_type, msg_body])
            

    def run(self):
        # send a gratuitous pong
        self.socket.send_multipart(['', 'pong', ''])
        main_thread = gevent.spawn(self.loop)
        gevent.joinall([main_thread])


# configure here
blastbeat = BlastBeatConsumer('tcp://192.168.173.5:5000', 'FOOBAR1')
blastbeat.run()
