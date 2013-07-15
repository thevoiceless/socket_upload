Simple programs for uploading data using sockets.
=====

This code was intended to be a proof-of-concept, and therefore is neither robust nor extremely well-written. `SocketUpload` is primarily intended for sending POST requests to `SimpleHTTPServerWithUpload`. `socket_upload_ssl` makes SSL-encrypted PUT requests to an Amazon S3 bucket.

Files
-----
* `SimpleHTTPServerWithUpload.py` - Extension of Python's `SimpleHTTPServer`. All credit goes to [Tao Huang](https://gist.github.com/UniIsland/3346170).
* `SocketUpload.java` - Uses the `SocketChannel` class to upload a file using a generic PUT or POST request to a given hostname.
* `socket_upload_ssl.cpp` - C++ code that uses the [PolarSSL](https://polarssl.org/) library to upload a file to an Amazon S3 bucket using a PUT request.
* `Makefile` - Compile/clean the code.

Caveats
-----
* `SocketUpload` was only tested against `SimpleHTTPServerWithUpload`.
* `socket_upload_ssl` was only tested against a completely barebones S3 bucket.
* PUT operations via `SocketUpload` were not tested because `SimpleHTTPServerWithUpload` does not support it.
* When using `SocketUpload` to POST to `SimpleHTTPServerWithUpload`, the server's response is not returned correctly (regardless of whether the upload was successful).
* `SocketUpload` uses `SocketChannel` and lacks SSL support because it was written to run against [Avian](https://github.com/ReadyTalk/avian) rather than the JVM
* The code always PUTs/POSTs to the filesystem root (no subdirectories).
* `socket_upload_ssl` does not handle any Amazon-specific header elements and only supports virtual hosted-style hostnames (i.e. bucketname.s3.amazonaws.com).
* `socket_upload_ssl` does not send the MD5 hash of the request contents.