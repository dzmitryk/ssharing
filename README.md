ssharing
========
SSH to HTTP file sharing server.

Example
========
* Register user: `ssh new-user@ssharing.myhost.com`
* Send file: `scp file-to-share.txt new-user@ssharing.myhost.com:`
* Receive file by opening `http://ssharing.myhost.com/new-user/file-to-share.txt` in your browser

How this works?
========
ssharing server is just piping input it receives from scp to an http response. Transferred files are not stored on the server. When scp transfer is initiated it will wait until http request to download the file is received, transfer begins only then. That is, the file is transferred to the first user requested it, for another user to download it `scp` command has to be issued again.

Configuration
========
JSON configuration file named `ssharing.conf` populated with the defaults is created in the working directory if it doesn't exist. Sample configuration file with all available options is listed below.

```json
{
	"SshKeyLocation":"keys/id_rsa",
	"UsersDir":"users/",
	"SshPort":":2222",
	"HttpPort":":8080",
	"EnableTls":"true",
	"TlsCertLocation":"cert/server.crt",
	"TlsKeyLocation":"cert/server.key"
}
```
