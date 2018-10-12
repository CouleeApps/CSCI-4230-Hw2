1. NEEDHAM-SCHROEDER SYMMETRIC KEY PROTOCOL

This protocol is Needham-Schroeder modified by Denning to include timestamps on messages 2 and 3.
The basic Needham-Schroeder uses a 5-step key distribution and handshake process to establish
a shared private session key between Alice and Bob, using a Key Distribution Center to store
and retrieve their symmetric encryption keys. Timestamps are added to messages 2 and 3 with
a valid period of 10 seconds to prevent replay attacks more than 10 seconds after the initial
connection is made.

Packets use the format <msg number><packet data> where <msg number> corresponds to which
step of the Needham-Schroeder exchange is taking place. Packet data is serialized and
deserialized for each type of message in needham-schroeder.h using a character stream.
The basic idea is that all values are converted into their representation in bytes and
strung together into one long stream. My pride and joy, the CharStream class, is basically
a big queue of arbitrary data types serialized into a character array. Values such as
integers are split into bytes and pushed as-is, while values such as IDs (in the form of
sockaddr_in structs) are pushed as their memory representation.

Encrypted blocks are stored in the form <length><encrypted bytes> where length is a 16-bit
integer. They can be created with the encrypt<T>(T, key) function and decrypted with
decrypt<T>(buffer, key). Currently they are using the toy DES from homework 1 with a 10-bit
key.



2. DIFFIE-HELLMAN KEY EXCHANGE:

To send their private keys to the Key Distribution Center, clients perform a Diffie-Hellman key
exchange. The server sends all connecting clients its public key and clients send the server
their public key. Both sides use these keys and the constant parameters q and alpha to generate
the same 10-bit symmetric session key. This implementation only uses 16 bit Diffie-Hellman keys
because the DES key size is so laughably small that there's no point in using bigger numbers.

The chosen constants for this Diffie-Hellman system are:
q = 15373 (prime)
alpha = 129 (primitive root of q)

Then both client and server pick a random number mod q as x (private key) and compute...
y = alpha ^ x mod q
... for their public key. After the exchange, both sides raise the other's public key to
the value of their private key to obtain the session key:

S_A = y_A ^ x_B = (alpha ^ x_A) ^ x_B mod q
S_B = y_B ^ x_A = (alpha ^ x_B) ^ x_A mod q = alpha ^ x_A ^ x_B mod q

And thus both sides can obtain the same shared secret session symmetric key without sending
any private information over a public channel.



BUILDING & RUNNING

Building this requires CMake 3.0+ and C++11 or higher.
To build:
cmake . && make

To run the server:
./server
Listens on port 12345

To run the client:
./client
Once two clients have registered you can initiate a Needham-Schroeder handshake between them
by typing the ip for one into the stdin of the other. Eg:

127.0.0.1 51179

If the handshake is successful you should see something like this:

[server]
Client 127.0.0.1:51292 requesting info for 127.0.0.1:51286

[client 1]
Got session key: 950
Established connection, got NS4 nonce: 145
NS handshake success

[client 2]
Got session key: 950
Send NS4 nonce: 145
Established connection, NS5 f(nonce2) match!
NS handshake success
