# MySQL Server Detector

Detects if MySQL server is running on a given IP and port, using a single handshake message from the server.

## Run

Built using Golang, run:

`go run mysql_script.go -ip IP -port PORT` 

_defaults to 127.0.0.1:3306_

## Test

Tested using go1.25.4 and MySQL versions: 9.1, 8.1, 5.7 and 5.5.

For a simple test, use **db4free.net**'s public MySQL server: 

`go run mysql_script -ip $(dig +short db4free.net | head -n1) -port 3306`

For extensive testing, and to increase test cases, use Docker to expose arbitrary MySQL servers. Current testing supports:

1. docker run -d -p 9991:3306 -e MYSQL_ROOT_PASSWORD=pass mysql:9.1
2. docker run -d -p 9981:3306 -e MYSQL_ROOT_PASSWORD=pass mysql:8.1 
3. docker run -d -p 9957:3306 -e MYSQL_ROOT_PASSWORD=pass biarms/mysql:5.7.30-linux-arm64v8
4. docker run -d -p 9955:3306 -e MYSQL_ROOT_PASSWORD=pass biarms/mysql:5.5.62-linux-arm64v8--beta-circleci

With these set up, run:

`go test`

## Todos

1. The code currently supports any MySQL server, but has not been tested on really old versions (ProtocolV9, and 4.x etc.).
2. Avoid detecting other tools that rely on the same handshake protocol as MySQL server (e.g., MariaDB).
