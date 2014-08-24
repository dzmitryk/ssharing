package main

import (
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"encoding/json"

	"code.google.com/p/go.crypto/bcrypt"
	"code.google.com/p/go.crypto/ssh"
)

const (
	DEFAULT_SSH_KEY_LOCATION = "keys/id_rsa"
	USERS_DIR                = "users/"
	DEFAULT_SSH_PORT         = ":2222"
	DEFAULT_HTTP_PORT        = ":8080"

	CONF_FILE              = "ssharing.conf"
	CONF_SSH_KEY_LOCATION  = "ssh_key_location"
	CONF_USERS_DIR         = "users_dir_location"
	CONF_SSH_PORT          = "ssh_port"
	CONF_HTTP_PORT         = "http_port"
	CONF_ENABLE_TLS        = "enable_tls"
	CONF_TLS_CERT_LOCATION = "tls_cert_location"
	CONF_TLS_KEY_LOCATION  = "tls_key_location"
)

type Upload struct {
	path     string
	writer   chan<- http.ResponseWriter
	complete <-chan bool
}

type Configuration struct {
	SshKeyLocation  string
	UsersDir        string
	SshPort         string
	HttpPort        string
	EnableTls       bool
	TlsCertLocation string
	TlsKeyLocation  string
}

var uploadMap map[string]Upload
var config Configuration

func loadConfiguration() Configuration {
	if _, err := os.Stat(CONF_FILE); err == nil {
		jsonConf, err := ioutil.ReadFile(CONF_FILE)

		if err != nil {
			log.Fatal("Can't read configuration file", err)
		}

		conf := Configuration{}

		err = json.Unmarshal(jsonConf, &conf)

		if err != nil {
			log.Fatal("Failed to parse configuration file", err)
		}

		return conf
	}

	conf := Configuration{SshKeyLocation: DEFAULT_SSH_KEY_LOCATION, UsersDir: USERS_DIR, SshPort: DEFAULT_SSH_PORT, HttpPort: DEFAULT_HTTP_PORT, EnableTls: false}

	jsonConf, _ := json.Marshal(&conf)
	err := ioutil.WriteFile(CONF_FILE, jsonConf, 0644)

	if err != nil {
		log.Panic("Failed to create configuration file", err)
	}

	return conf
}

func newUser(name string, pass []byte) {
	hash, err := bcrypt.GenerateFromPassword(pass, bcrypt.DefaultCost)

	if err != nil {
		log.Panic("Failed to generate password hash", err)
	}

	userData := map[string]string{
		"name": name,
		"hash": string(hash),
	}

	jsonUserData, _ := json.Marshal(userData)

	err = ioutil.WriteFile(config.UsersDir+name, jsonUserData, 0644)

	if err != nil {
		log.Panic("Failed to write user data file", err)
	}
}

func findUser(name string) map[string]string {
	userFilePath := config.UsersDir + name

	if _, err := os.Stat(userFilePath); err == nil {
		jsonUserData, err := ioutil.ReadFile(userFilePath)

		if err != nil {
			log.Panic("Failed to retrieve user information", err)
		}

		var userData map[string]string

		err = json.Unmarshal(jsonUserData, &userData)

		if err != nil {
			log.Panic("Failed to unmarshal user data file", err)
		}

		return userData
	}

	return nil
}

func passwordCallback(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	userData := findUser(c.User())

	if userData == nil {
		newUser(c.User(), pass)
		return nil, nil
	}

	err := bcrypt.CompareHashAndPassword([]byte(userData["hash"]), pass)

	if err != nil {
		return nil, err
	}

	return nil, nil
}

func handleScpFileTransfer(channel ssh.Channel, destDir string) error {
	// send zero byte to tell scp on the other side we're ready to proceed...
	channel.Write([]byte{0})

	readBuf := make([]byte, 256)

	go func() {
		defer channel.Close()

		bytesRead, err := channel.Read(readBuf)

		if err != nil {
			log.Panic("Error reading data", err)
		}

		cmdLine := strings.Trim(string(readBuf[:bytesRead]), "\n ")

		cmdParts := strings.Split(cmdLine, " ")

		code := string([]rune(cmdParts[0])[0])

		// handle only single file transfer - scp command starting with "C"
		if code == "C" {
			// for now ignoring file mode

			// extract byte length of transferred file
			fileLength, err := strconv.Atoi(cmdParts[1])

			if err != nil {
				log.Panic("Can't parse scp command", err)
			}

			// file name of transferred file
			fileName := cmdParts[2]

			path := destDir + "/" + fileName

			writer := make(chan http.ResponseWriter)
			complete := make(chan bool)

			uploadMap[path] = Upload{path, writer, complete}

			w := <-writer

			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", strconv.Itoa(fileLength))

			channel.Write([]byte{0})

			// copy file content to to http response writer
			_, err = io.CopyN(w, channel, int64(fileLength))

			if err != nil {
				// just log error for now
				log.Println(err)
			}

			// respond with zero byte to confirm transfer success
			channel.Write([]byte{0})

			// tell http request handler that we're finished
			complete <- true
		}

	}()

	return nil
}

func listenSsh(addr string, config *ssh.ServerConfig) {
	listener, err := net.Listen("tcp", addr)

	if err != nil {
		log.Panic("Failed to start listening", err)
	}

	for {
		conn, err := listener.Accept()

		if err != nil {
			log.Println("Error establishing connection", err)

			continue
		}

		go handleSshConnection(conn, config)
	}
}

func handleSshConnection(conn net.Conn, config *ssh.ServerConfig) {

	serverCon, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Panic("Handshake failed", err)
	}

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {

		channel, requests, err := newChannel.Accept()

		if err != nil {
			log.Panic("Error accepting request", err)
		}

		go func(in <-chan *ssh.Request) {
			for req := range in {
				switch req.Type {
				case "shell":
					req.Reply(true, nil)
					channel.Close()
				case "exec":
					req.Reply(true, nil)
					go handleScpFileTransfer(channel, serverCon.User())
				}
			}
		}(requests)
	}
}

func listenHttp(addr string, tls bool) {
	http.HandleFunc("/", handleHttpRequest)

	var err error

	if tls {
		err = http.ListenAndServeTLS(addr, config.TlsCertLocation, config.TlsKeyLocation, nil)
	} else {
		err = http.ListenAndServe(addr, nil)
	}

	if err != nil {
		log.Panic(err)
	}
}

func handleHttpRequest(writer http.ResponseWriter, request *http.Request) {
	path := strings.Split(strings.Trim(request.URL.Path, "/"), "/")

	if len(path) == 2 {
		filePath := path[0] + "/" + path[1]

		if upload, ok := uploadMap[filePath]; ok {
			upload.writer <- writer

			<-upload.complete
			delete(uploadMap, filePath)
		} else {
			http.NotFound(writer, request)
		}
	} else {
		http.NotFound(writer, request)
	}
}

func main() {
	config = loadConfiguration()

	// prepare directory layout
	os.Mkdir(config.UsersDir, 0744)

	sshServerConfig := &ssh.ServerConfig{
		PasswordCallback: passwordCallback,
	}

	privateBytes, err := ioutil.ReadFile(config.SshKeyLocation)
	if err != nil {
		log.Fatal("Failed to load private key", err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key", err)
	}

	sshServerConfig.AddHostKey(private)

	uploadMap = make(map[string]Upload)

	go listenSsh(config.SshPort, sshServerConfig)

	// start http server
	listenHttp(config.HttpPort, config.EnableTls)
}
