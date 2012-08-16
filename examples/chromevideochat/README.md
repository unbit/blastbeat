Building a VideoChat with Websockets and BlastBeat pipes
=========

This example/tutorial will show you how to use the 'pipe' system of BlastBeat to forward
big messages (like video frames) to peers/groups with efficiency and speed. The example works
in Chrome 21.

Video frames and control messages (like joining channel or sending text messages) will be managed by two different
Websocket connections.

Supposing our BlastBeat server is on 127.0.0.1:8080 we will use **ws://127.0.0.1:8080/control** for control messages (they will be json
objects) and **ws://127.0.0.1:8080/data/-cookie-** for video frames. 

-cookie- will be a code returned by the control channel to authorize the user to send/receive videoframes.


### Getting access to the WebCam in chrome

```javascript

function webcam_ok(stream) {
  var output = document.getElementById('output');
  var source = window.webkitURL.createObjectURL(stream);
  output.src = source;
}

function webcam_no() {
  alert('no access to the webcam');
}

navigator.webkitGetUserMedia({video: true, audio: true}, webcam_ok, webcam_no);

```

When we ask for webcam access via the **webkitGetUserMedia** function, we will be prmpted for authorization by the browser.
If we confirm, the webcam_ok() function will be called, passing the webcam stream object to it.

Then we build a custom url from the stream and we set it as the src of a video object named 'output'

```html
<video id="output" autoplay></video>
```

remember to set autoplay, otherwise the video will be stopped.

NOTE: currently (chrome version 21) microphone support is incomplete, so we will be able to send video frame only

### Ask a cookie to our BlastBeat app for getting access to the pipe system

After getting access to our webcam, we want to 'enter' the chat and get a 'cookie' for connecting to the 'data' service.


