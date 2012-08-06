#
# This example shows the usage of the blastbeat gem
# Whenever a client connects to blastbeat all of the already connected peers will
# receive a message.
#
# to Test it simply launch (in multiple terminals):
# curl -N http://<server>:<port>/
# Running it into a browser will probably never work, as browsers tend to buffer datas
#
# The examples show the usage of 'msg' type for internal communication
#
# 'msg' can route to a sid or a to a group. In this example we use groups 
#
# at the beginning of every session, a 'join' to the group 'peers' is called
#
# Each session maps to a Thread, this is not very efficient, but should give you some funny idea
#
# When a session receives the 'end' message, the thread is destroyed
#
# NOTE: very probably direclt sending 'chunk' messages to a group is a lot more efficient...but i
# need a way to show the usage of the 'msg' type :P

require 'blastbeat'
require 'thread'

Thread.abort_on_exception = true

# CONFIGURE HERE
blastbeat = BlastBeat::Node.new('tcp://192.168.173.5:5000', 'FOOBAR1')

# global hash of sessions
$sessions = {}
# send a gratuitous pong (a trick for letting BlastBeat knowing about us as soon as possibile)
blastbeat.send('', 'pong')

# this class maps to a session/thread
class BlastBeatSession

  attr_accessor :queue

  def session_loop
    while true
      # dequeue messages
      msg_type, msg_body = @queue.pop
      # if the message is 'uwsgi' the session just started
      if msg_type == 'uwsgi'
        # parse the request (pretty useless here)
        environ = @blastbeat.uwsgi(msg_body)
        # send headers (pay attention to the Transfer-Encoding: chunked part)
        @blastbeat.send(@sid, 'headers', "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n")
        # join the 'peers' group
        @blastbeat.send(@sid, 'join', 'peers')
        # send an internal message to all of the group members
        @blastbeat.send(@sid, 'peers:msg', "#{Time.now} #{$sessions.length} peers connected\n")

      # internal messages are forwarded as chunked body to the client
      elsif msg_type == 'msg'
          @blastbeat.send(@sid, 'chunk', msg_body)
      # end the thread
      elsif msg_type == 'end'
          $sessions.delete(@sid)
          return
      end

    end 

  end

  def initialize(blastbeat, sid)
    @blastbeat = blastbeat
    @sid = sid
    @queue = Queue.new
    thread = Thread.new { session_loop }
  end
end

# main loop
while true
  # dequeue BlastBeat messages
  sid,msg_type,msg_body = blastbeat.recv
  # respond to ping
  if msg_type == 'ping'
    blastbeat.send(sid, 'pong')
    next
  end
  # respond to end
  if msg_type == 'end'
    next unless $sessions.has_key?(sid)
    $sessions[sid].queue << [msg_type,msg_body]
    next
  end

  # create a new session if not available
  if not $sessions.has_key?(sid)
    $sessions[sid] = BlastBeatSession.new(blastbeat, sid)
  end
  
  # enqueue the message
  $sessions[sid].queue << [msg_type,msg_body]
    
end
