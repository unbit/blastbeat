#include "../blastbeat.h"

/*

BlastBeat group management

Each virtualhost has its pool of groups.

Each group has a name in a hash table.

A group has a linked list of associated sessions
Each session has a linked list of all the subscribed groups

To join/create a group you send

SID, "join", "name"

if "name" already exists you will join the group, otherwise it will be created

To send a message to a group, you prefix it to the command:

SID, "mygroup:body", "<h1>Hello World</h1>"

this will send the body to all of the connected peers

When a session ends, it will be removed from all of the subscribed groups

*/
