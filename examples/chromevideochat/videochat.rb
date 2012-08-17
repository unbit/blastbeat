require 'blastbeat'
require 'json'

# CONFIGURE HERE
blastbeat = BlastBeat::Node.new('tcp://192.168.173.5:5000', 'FOOBAR1')

# the global hash of sessions
$sessions = {}
# the global hash of cookies
$cookies = {}
# a global integer for assigning an id to each user
$users_id = 0
# send a gratuitous pong (a trick for letting BlastBeat knowing about us as soon as possibile)
blastbeat.send('', 'pong')

# this class maps to a session/thread
class BlastBeatSession

  attr_reader :id, :cookie

  def manage_command(body)
    j = JSON.parse(body)
    case j['command']
      when 'text'
        @blastbeat.send(@sid, 'videochat:websocket', body)
      when 'join'
        @blastbeat.send(@sid, 'join', 'videochat')
        $users_id+=1
        @id = $users_id
        @cookie = rand(36**8).to_s(36)
        $cookies[@cookie] = self
        users = []
        for session_id in $sessions.keys
            next if session_id == @sid
            users << $sessions[session_id].id 
        end
        welcome = {'command' => 'welcome', 'id' => @id, 'cookie' => @cookie, 'users' => users }
        @blastbeat.send(@sid, 'websocket', JSON.generate(welcome))
        newuser = {'command' => 'newuser', 'id' => @id}
        @blastbeat.send(@sid, 'videochat:websocket', JSON.generate(newuser))
    end
  end

  def run(msg_type, msg_body)
      # if the message is 'uwsgi' the session just started
      if msg_type == 'uwsgi'
        # parse the request (pretty useless here)
        environ = @blastbeat.uwsgi(msg_body)
        if environ['PATH_INFO'] == '/control'
            @type = 'control'
        elsif environ['PATH_INFO'][0,6] == '/data/'
            cookie = environ['PATH_INFO'][6, environ['PATH_INFO'].length]
            if not $cookies.has_key?(cookie)
                @blastbeat.send(@sid, 'end')
                $sessions.delete(@sid)
                return 
            end
            @type = 'data'
        end
      elsif msg_type == 'websocket'
        # start piping frames
        if @type == 'data' and msg_body == 'start'
          @blastbeat.send(@sid, 'join', 'videoframes')
          @blastbeat.send(@sid, 'noecho', 'videoframes')
          @blastbeat.send(@sid, 'pipe', 'videoframes:websocket')
        # a control message
        # {'command':'text', 'body':'hello'}
        elsif @type == 'control'
          manage_command(msg_body)
        end 
      end
  end

  def initialize(blastbeat, sid)
    @blastbeat = blastbeat
    @sid = sid
    @type = nil
    @cookie = nil
    @id = nil
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
    byeuser = {'command' => 'byeuser', 'id' => $sessions[sid].id }
    for user_sid in $sessions.keys
      blastbeat.send(user_sid, 'websocket', JSON.generate(byeuser))
    end
    $cookies.delete( $sessions[sid].cookie )
    $sessions.delete(sid)
    next
  end

  # create a new session if not available
  if not $sessions.has_key?(sid)
    $sessions[sid] = BlastBeatSession.new(blastbeat, sid)
  end
  
  $sessions[sid].run(msg_type,msg_body)
    
end
