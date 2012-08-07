# A Multiuser websocket-based chat using ruby fibers for concurrency
#
# each active session id is mapped to a BlastBeatFiberSession object
# spawning a ruby 1.9 fiber. The fiber will looply consume messages
# from a global queue and will yield after each iteration
#
# on websocket connection (read: when the 'uwsgi' message is received)
# the session will join the 'fiberchat' group
#
# from now on, every 'websocket' message will be forwarded to all of the subscribed peers
#
# A Note on 'end' management:
#
# if the application dies while a session on the blastbeat server is active
# a new instance of the application could receive the 'end' message. You can simply ignore that...
# That's why you will see the main cycle managig 'end' (in addition to 'ping') messages
#

require 'blastbeat'
require 'fiber'

# connect to the blastbeat server
# CONFIGURE HERE AND REMEMBER TO CHANGE THE WEBSOCKET ADDRESS IN THE HTML FILE
blastbeat = BlastBeat::Node.new('tcp://192.168.173.5:5000', 'FOOBAR1')
# gratuitous pong
blastbeat.send('', 'pong')

# the global hash for sessions
$sessions = {}
# the global queue (it is a simple array)
$queue = []

# commodity class to manage sessions
class BlastBeatFiberSession

  attr_accessor :fiber

  # this is run into the fiber
  def session_loop
    loop do
      msg_type, msg_body = $queue.pop
      case msg_type
        # on 'uwsgi' message join the 'fiberchat' group
        when 'uwsgi'
          @blastbeat.send(@sid, 'join','fiberchat')
        # forward the message to all of the peers (myself included)
        when 'websocket'
          @blastbeat.send(@sid, 'fiberchat:websocket', msg_body)
        # end the fiber and delete the object from the global sessions hash
        when 'end'
          $sessions.delete(@sid)
          return
        # oops
        else
          puts "unmanaged message type: #{msg_type}"
      end
      # give control back to the main cycle
      Fiber.yield
    end
  end

  def initialize(blastbeat, sid)
    @blastbeat = blastbeat
    @sid = sid
    # create the fiber
    @fiber = Fiber.new do
      Fiber.yield
      session_loop
    end 
    # start it (will suddenly yield)
    @fiber.resume
  end

end

# main loop (consuming blastbeat messages)
loop do
  sid, msg_type, msg_body = blastbeat.recv

  # manage ping
  if msg_type == 'ping'
    blastbeat.send(sid, 'pong')
    next
  end

  # manage disconnections (REMEMBER you could receive disconnections for old sessions !!!)
  if msg_type == 'end'
    next unless $sessions.has_key?(sid)
    $queue << [msg_type, msg_body]
    $sessions[sid].fiber.resume
    next
  end

  # create the new session object
  unless $sessions.has_key?(sid)
    $sessions[sid] = BlastBeatFiberSession.new(blastbeat, sid)
  end

  # enqueue the message
  $queue << [msg_type, msg_body]

  # give control to the fiber
  $sessions[sid].fiber.resume
end
