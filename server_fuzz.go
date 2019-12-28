// +build gofuzz

package pop3

import (
	"io"
	"net"
)

var server = &Server{
	Auth: &auth{
		m: &memoryMaildrop{
			messages: map[string]string{
				"foo":    "first",
				"bar":    "second",
				"foobar": "third",
			},
		},
	},
}

var done = make(chan struct{})
var ln net.Listener

// TODO(dzeromsk): remove tcp/ip stuff
func init() {
	var err error
	ln, err = net.ListenTCP("tcp", nil)
	if err != nil {
		panic(err)
	}

	go func() {
		if err := server.Serve(ln); err != nil {
			panic(err)
		}
		close(done)
	}()
}

func Fuzz(data []byte) int {
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return 0
	}
	defer conn.Close()

	_, err = conn.Write(data)
	if err != nil {
		return 0
	}

	return 1
}

type auth struct {
	m Maildropper
}

func (a *auth) Auth(user, pass string) (Maildropper, error) {
	return a.m, nil
}

type memoryMaildrop struct {
	messages map[string]string
}

func (m *memoryMaildrop) List() (sizes map[string]int, err error) {
	sizes = make(map[string]int)
	for k, v := range m.messages {
		sizes[k] = len(v)
	}

	return sizes, nil
}

func (m *memoryMaildrop) Get(key string, message io.Writer) (err error) {
	message.Write([]byte(m.messages[key]))
	return nil
}

func (m *memoryMaildrop) Delete(key string) (err error) {
	delete(m.messages, key)
	return nil
}
