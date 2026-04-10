A rust implementation of [RFC7016](https://tools.ietf.org/html/rfc7016)


### Testing
Run a RTMFP server
```shell
docker run -it --rm -p 80:80 -p 1935:1935 -p 554:554 -p 1935:1935/udp monaserver/monaserver
```