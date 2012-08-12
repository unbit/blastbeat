# A socket.io ruby test app
#
# in addition to socket.io messages it shows how to send a file with chunked encoding
#

require 'blastbeat'

# connect to the blastbeat server
# CONFIGURE HERE AND REMEMBER TO CHANGE THE SOCKET.IO ADDRESS IN THE HTML FILE
blastbeat = BlastBeat::Node.new('tcp://192.168.173.5:5000', 'FOOBAR1')
# gratuitous pong
blastbeat.send('', 'pong')

# main loop (consuming blastbeat messages)
loop do
  # get blastbeat message
  sid, msg_type, msg_body = blastbeat.recv

  # manage ping
  case msg_type
    when 'ping'
      blastbeat.send(sid, 'pong')
    when 'uwsgi'
      environ = blastbeat.uwsgi(msg_body)
      if environ['PATH_INFO'] == '/siotest.html'
        # build the html filename
        filename = File.expand_path(File.dirname(__FILE__))+'/siotest.html'
        # send headers specifying chunked mode 
        blastbeat.send(sid, 'headers', "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n")
        # send the file in chunks
        f = File.open(filename, 'rb') do |f|
          blastbeat.send(sid, 'chunk', f.read(4096)) until f.eof?
        end
        # send the ending chunk
        blastbeat.send(sid, 'chunk')
      end
  # echo back the events
    when 'socket.io/event'
      blastbeat.send(sid, 'socket.io/event', msg_body)
    when 'socket.io/msg'
    blastbeat.send(sid, 'socket.io/msg', msg_body)
    when 'socket.io/json'
      blastbeat.send(sid, 'socket.io/json', msg_body)
  end
end
