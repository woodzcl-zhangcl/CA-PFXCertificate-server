Hi, guys!
I am a developer in c/c++.
Now, I support a project about a server issuing pfx certificate with open source, depending on openssl.
As I am not familiar with cmake or perl, so I just only contribute raw source.
Please, someone can help write a general method to compile this project. I can support makefile to do that, but I don't want to do.

function in this project:
1. server generate pkcs10.
2. putting sign x509 certificate, server generate sign pkcs12 certificate, then transfering it to client
3. putting encrypt x509 certificate, server generate encrypt pkcs12 certificate, then transfering it to client
