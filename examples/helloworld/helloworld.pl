use ZeroMQ qw/:all/;

my $ctx = ZeroMQ::Context->new;
my $socket = $ctx->socket(ZMQ_DEALER);
$socket->setsockopt(ZMQ_IDENTITY, 'FOOBAR1');
$socket->connect('tcp://192.168.173.5:5000');

# gratuitous pong
enqueue($socket, '', 'pong');

while(1) {
	
	my ($sid, $msg_type, $msg_body) = dequeue($socket);

	if ($msg_type eq 'ping') {
		enqueue($socket, $sid, 'pong');
		next;
	}

	if ($msg_type eq 'uwsgi') {
		enqueue($socket, $sid, 'headers', "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n");
		enqueue($socket, $sid, 'body', '<h1>Hello World, i am BlastBeat</h1>');

		enqueue($socket, $sid, 'body', '<table border="1">');

		my %environ = uwsgi($msg_body);
		foreach my $key (keys %environ) {
			enqueue($socket, $sid, 'body', '<tr><td><b>'.$key.'</b></td><td>'.$environ{$key}.'</td></tr>') ;
		}

		enqueue($socket, $sid, 'body', '</table>');

		# store something in the cache (this is more a tent than a simple helloworld)
		# some item is wrong... just for testing cache strength...
		enqueue($socket, $sid, 'cache', "/foobar001 17 1\r\nHTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\n<h1>I Am from CaChe</h1>");
		enqueue($socket, $sid, 'cache', "/foobar002 30\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>I Am from CaChe 2</h1>");
		enqueue($socket, $sid, 'cache', "/foobar003 10\r\nHTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n<h1>I Am from CaChe 3</h1>");

		enqueue($socket, $sid, 'cache', "/foobar004 10\r\nTEST/0.0 404 Not Found\r\nContent-Type: text/plain\r\n\r\n<h1>I Am from CaChe 3</h1>");
		enqueue($socket, $sid, 'cache', "/foobar005 10\r\nHTTP/1.0\r\nContent-Type: text/plain\r\n\r\n<h1>I Am from CaChe 3</h1>");
		enqueue($socket, $sid, 'cache', "/foobar006\r\nHTTP/1.0 200 OK\r\n\r\nAm from CaChe 3</h1>");

		enqueue($socket, $sid, 'end');
	}

}


sub dequeue {
	my ($socket) = @_;
	my $sid = $socket->recv()->data;
        my $msg_type = $socket->recv()->data;
        my $msg_body = $socket->recv()->data;
	return ($sid, $msg_type, $msg_body);
}

sub enqueue {
	my ($socket, $sid, $msg_type, $msg_body) = @_;

	$msg_body = '' unless $msg_body;
	
	my $zm_sid = ZeroMQ::Message->new($sid);
	my $zm_mt = ZeroMQ::Message->new($msg_type);
	my $zm_mb = ZeroMQ::Message->new($msg_body);

	$socket->send($zm_sid, ZMQ_SNDMORE);
	$socket->send($zm_mt, ZMQ_SNDMORE);
	$socket->send($zm_mb);
}

sub uwsgi {
	my ($pkt) = @_;
	my ($ulen) = unpack('v', substr($pkt, 1, 2));
      	my $pos = 4;
	my %h;
	while ($pos < $ulen) {
        	my ($klen) = unpack('v', substr($pkt, $pos, 2));
        	my $k = substr($pkt, $pos+2, $klen); $pos += 2+$klen;
        	my ($vlen) = unpack('v', substr($pkt, $pos, 2));
        	my $v = substr($pkt, $pos+2, $vlen); $pos += 2+$vlen;
		$h{$k} = $v;
	}
	return %h;
}
