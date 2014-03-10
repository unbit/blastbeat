#!/usr/bin/php
<?php
// Requires ZMQ pecl extension

/* Create new queue object */
$queue = new ZMQSocket(new ZMQContext(), ZMQ::SOCKET_DEALER);

$queue->setSockOpt(ZMQ::SOCKOPT_IDENTITY,'FOOBAR1');

/* Connect to an endpoint */
$queue->connect("tcp://127.0.0.1:5000");

/* receive */
while(1) {
  $data=$queue->recvMulti();
  // sid, when set, are 16 bytes long (packed binary)
  list($sid,$type,$body)=$data;
  switch($type) {
    case 'ping':
      $queue->sendmulti(array($sid,'pong','pong'));
    break;
    case 'websocket':
      //echo "ws [$sid/$body]\n";
      $queue->sendmulti(array($sid,'websocket','recv: '.$body));
    break;
    // can use SPDY_VERSION to tell difference between HTTP and SPDY
    case 'uwsgi':
      //echo "uwsgi\n";
      //echo ".";
      list(,$ulen)=unpack('v',substr($body,1,2));
      $env=array(); // clear last environment if there was one
      $pos=4;
      while($pos<$ulen) {
        $next=substr($body,$pos,2);
        //echo "reading 2 bytes @[$pos] [$next]<br>\n";
        list(,$klen)=unpack('v',$next);
        $k=substr($body,$pos+2,$klen);
        //echo "klen[$klen] k[$k]<br>\n";
        $pos+=2+$klen;

        $next=substr($body,$pos,2);
        //echo "reading 2 bytes @[$pos] [$next]<br>\n";
        list(,$vlen)=unpack('v',$next);
        $v=substr($body,$pos+2,$vlen);
        //echo "vlen[$vlen] v[$v]<br>\n";
        $pos+=2+$vlen;
        //echo "[$k=$v]\n";
        $env[$k]=$v;
      }
      // you have to becareful of what headers you send, if it's not parseable by http_parser,
      // your request can fail
      $headers=array($env['SERVER_PROTOCOL'].' 200 Ok',
        'Content-Type: text/html','Host: '.$env['HTTP_HOST'],
        '',''); // leave last two blank to signal end
      $queue->sendmulti(array($sid,'headers',join("\r\n",$headers)));
      if (isset($env['SPDY_VERSION'])) {
        $pushheaders=array($env['SERVER_PROTOCOL'].' 200 Ok',
          ':scheme: '.$env['SERVER_SCHEME'],':host: '.$env['HTTP_HOST'],
          ':path: /test1.js',
          'Content-Type: text/javascript',
          '',''); // leave last two blank to signal end
        $queue->sendmulti(array($sid,'push',join("\r\n",$pushheaders)));
        $queue->sendmulti(array($sid,'body',"alert('hello');\n"));
        $queue->sendmulti(array($sid,'end',''));
      }
      $queue->sendmulti(array($sid,'body','<script type="text/javascript" src="/test1.js"></script>'));
      $queue->sendmulti(array($sid,'end',''));
    break;
    default:
      $hrsid='';
      if ($sid) {
        list(,$hrsid)=unpack('H16',$sid);
      }
      echo "unknown type[$type] $hrsid/$body\n";
    break;
  }
}

?>
