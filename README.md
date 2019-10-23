
Golang HTTP server
=========

This is simple HTTP server written in Go. The server retrieves and serves live E-sport data from Abios server.



# Installation

## Get the package
To give it a spin, first get the package with:

```shell
go get github.com/johnnyflame/abios-toy-project

```
This will retrieve the sourcecode to your Go workspace directory. 

## Build


First make sure you have Docker installed on your machine. 

Then navigate to the directory with the source files, add the following to the dockerfile, make sure replace "YOUR_CLIENT_ID" and "YOUR_PASSWORD" with real credentials from Abios:

```docker
ENV USERNAME  "YOUR_CLIENT_ID"
ENV PASSWORD "YOUR_PASSWORD"
```

Now we're ready to roll! To build, run the following:

```shell
docker-compose up --build
```

This will build and fire up a container called Abios-toy-server, which listens for requests on port 8080.

# Usage

There are 3 end points in this server, these are:

1. /series/live  
2. /players/live
3. /teams/live 


These endpoints corrosponds to live series data, live players data, and live teams data respectively.

