/*

	Using dealer identity as authentication is insecure.

	You can use that for simple systems, or where dealers are fully trusted

	Scenario:

		2 dealers, 1 is evil.

		Both set identity as 'foobar', the first connecting one
		get power.

		If the evil one is the first connecting we lose.

		If the good one, fails, the evil one will (soon or later) get power. we lose again :(

	Solution: using cookie based identity (each dealer requires a valid certificate, signed by a ca configured per server/virtualhost)

		A ZMQ_REP is bound on a specific address (can be server-wide or virtualhost-related)
		this is called the 'authenticator' service

		A dealer open a ZMQ_REQ to the authenticator and send a 'auth' message

		the 'auth' message is composed by two parts, the first one is the id of the dealer (required for crypting the response) and the second one
		is the command (in that case is 'auth')

		the server respond with an encrypted (just to be paranoid, see later) cookie, the dealer will use it as the identity.

		From now one the server (router) will accept only zmq messages with that identity instead of the deafult one (until a new 'auth' cookie is requested)


*/
