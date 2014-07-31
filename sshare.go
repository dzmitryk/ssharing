package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
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
	_KEYS_DIR        = "keys/"
	_USERS_DIR       = "users/"
	_USERS_DATA_ROOT = "userdata/"
)

func newUser(name string, pass []byte) {
	hash, err := bcrypt.GenerateFromPassword(pass, bcrypt.DefaultCost)

	if err != nil {
		panic("Failed to generate password hash")
	}

	userData := map[string]string{
		"name": name,
		"hash": string(hash),
	}

	jsonUserData, _ := json.Marshal(userData)

	err = ioutil.WriteFile(_USERS_DIR+name, jsonUserData, 0644)

	if err != nil {
		panic("Failed to write user data file")
	}

	os.Mkdir(_USERS_DATA_ROOT+name, 0744)
}

func findUser(name string) map[string]string {
	userFilePath := _USERS_DIR + name

	if _, err := os.Stat(userFilePath); err == nil {
		jsonUserData, err := ioutil.ReadFile(userFilePath)

		if err != nil {
			panic("Failed to retrieve user information")
		}

		var userData map[string]string

		err = json.Unmarshal(jsonUserData, &userData)

		if err != nil {
			panic("Failed to unmarshal user data file")
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
			panic("error reading data")
		}

		cmdLine := strings.Trim(string(readBuf[:bytesRead]), "\n ")

		cmdParts := strings.Split(cmdLine, " ")

		code := string([]rune(cmdParts[0])[0])

		// handle only single file transfer: scp command will start with "C"
		if code == "C" {
			// for now ignoring file mode

			// extract byte length of transferred file
			fileLength, err := strconv.Atoi(cmdParts[1])

			if err != nil {
				panic(err)
			}

			// file name of transferred file
			fileName := cmdParts[2]

			file, err := os.Create(destDir + "/" + fileName)
			defer file.Close()

			if err != nil {
				panic(err)
			}

			channel.Write([]byte{0})

			writer := bufio.NewWriter(file)

			for totalBytesRead := 0; totalBytesRead < fileLength; {

				bytesRead, err := channel.Read(readBuf)
				_, err = writer.Write(readBuf[:bytesRead])

				if err != nil {
					panic(err)
				}

				totalBytesRead += bytesRead
			}

			writer.Flush()

			// respond with zero byte to confirm transfer success
			channel.Write([]byte{0})

			if err != nil {
				panic("error reading data")
			}
		}

	}()

	return nil
}

func listenSsh(addr string, config *ssh.ServerConfig) {
	listener, err := net.Listen("tcp", addr)

	if err != nil {
		panic("Failed to start listening")
	}

	for {
		conn, err := listener.Accept()

		if err != nil {
			fmt.Println("Error establishing connection")

			continue
		}

		go handleSshConnection(conn, config)
	}
}

func handleSshConnection(conn net.Conn, config *ssh.ServerConfig) {

	serverCon, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		panic("Handshake failed")
	}

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {

		channel, requests, err := newChannel.Accept()

		if err != nil {
			panic("Error accepting request")
		}

		go func(in <-chan *ssh.Request) {
			for req := range in {
				switch req.Type {
				case "shell":
					req.Reply(true, nil)
					channel.Close()
				case "exec":
					req.Reply(true, nil)
					go handleScpFileTransfer(channel, _USERS_DATA_ROOT+serverCon.User())
				}
			}
		}(requests)
	}
}

func listenHttp(addr string) {
	http.HandleFunc("/", handleHttpRequest)

	err := http.ListenAndServe(addr, nil)

	if err != nil {
		panic("Couldn't start http server")
	}
}

func handleHttpRequest(writer http.ResponseWriter, request *http.Request) {
	path := strings.Split(strings.Trim(request.URL.Path, "/"), "/")

	if len(path) == 2 {
		filePath := fmt.Sprintf("%s%s/%s", _USERS_DATA_ROOT, path[0], path[1])

		fmt.Fprintf(writer, filePath)

		if _, err := os.Stat(filePath); err == nil {

		}
	} else {
		http.NotFound(writer, request)
	}
}

func main() {

	// prepare directory layout
	os.Mkdir(_KEYS_DIR, 0744)
	os.Mkdir(_USERS_DIR, 0744)
	os.Mkdir(_USERS_DATA_ROOT, 0744)

	config := &ssh.ServerConfig{
		PasswordCallback: passwordCallback,
	}

	privateBytes, err := ioutil.ReadFile(_KEYS_DIR + "id_rsa")
	if err != nil {
		panic("Failed to load private key")
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		panic("Failed to parse private key")
	}

	config.AddHostKey(private)

	go listenSsh(":2222", config)
	listenHttp(":8080")
}
