package pop3

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"regexp"
	"testing"
	"time"

	"github.com/google/goexpect"
)

const timeout = 1 * time.Second

func Example() {
	a := &auth{
		m: &memoryMaildrop{
			messages: map[string]string{
				"foo":    "Subject: first",
				"bar":    "Subject: second",
				"foobar": "Subject: thirdasdasd\n\ndas",
			},
		},
	}
	err := ListenAndServeTLS(":1995", "cert.pem", "key.pem", a)
	if err != nil {
		log.Fatalln(err)
	}
}
func TestPOP3Server(t *testing.T) {
	messages := map[string]string{
		"foo":    "first",
		"bar":    "second",
		"foobar": "third",
	}
	dummy := &auth{
		m: &memoryMaildrop{
			messages: messages,
		},
	}
	var tests = []struct {
		name string
		auth Authorizer
		cmd  []fmt.Stringer
		fail bool
	}{
		{
			name: "simple retr",
			auth: dummy,
			cmd: []fmt.Stringer{
				s(`\+OK Gpop ready for requests from .*`),
				c(`USER john`),
				s(`\+OK send PASS`),
				c(`PASS qwerty`),
				s(`\+OK welcome`),
				c(`LIST`),
				s(`\+OK 3 messages \(.+ octets\).*`),
				c(`RETR 1`),
				s(`\+OK . octets`),
				c(`RETR 2`),
				s(`\+OK . octets`),
				c(`RETR 3`),
				s(`\+OK . octets`),
				c(`QUIT`),
				s(`\+OK bye`),
			},
			fail: false,
		},
		{
			name: "fast quit",
			auth: dummy,
			cmd: []fmt.Stringer{
				s(`\+OK Gpop ready for requests from .*`),
				c(`QUIT`),
				s(`\+OK bye`),
			},
			fail: false,
		},
		{
			name: "transition to transaction state",
			auth: dummy,
			cmd: []fmt.Stringer{
				s(`\+OK Gpop ready for requests from .*`),
				c(`USER a b c`),
				s(`\+OK send PASS`),
				c(`PASS X Y Z`),
				s(`\+OK welcome home`),
			},
			fail: false,
		},
		{
			name: "invalid commands in authorization state",
			auth: dummy,
			cmd: []fmt.Stringer{
				s(`\+OK Gpop ready for requests from .*`),
				c(`STAT`),
				s(`-ERR malformed command`),
				c(`LIST`),
				s(`-ERR malformed command`),
				c(`RETR 1`),
				s(`-ERR malformed command`),
				c(`RETR`),
				s(`-ERR malformed command`),
				c(`DELE`),
				s(`-ERR malformed command`),
				c(`DELE 1`),
				s(`-ERR malformed command`),
				c(`NOOP`),
				s(`-ERR malformed command`),
				c(`RSET`),
				s(`-ERR malformed command`),
				c(`TOP`),
				s(`-ERR malformed command`),
				c(`UIDL`),
				s(`-ERR malformed command`),
				c(``),
				s(`-ERR malformed command`),
			},
			fail: false,
		},
		{
			name: "capabilities",
			auth: dummy,
			cmd: []fmt.Stringer{
				s(`\+OK Gpop ready for requests from .*`),
				c(`CAPS`),
				s(`-ERR malformed command`),
				c(`CAPA`),
				s(`\+OK Capability list follows`),
				// s(`USER`),
				// s(`STLS`),
				// s(`IMPLEMENTATION go-pop3`),
				// s(`\.`),
				c(`QUIT`),
				s(`\+OK bye`),
			},
			fail: false,
		},
		{
			name: "experimenting",
			auth: dummy,
			cmd: []fmt.Stringer{
				s(`\+OK Gpop ready for requests from .*`),
				c(`USER john`),
				s(`\+OK send PASS`),
				c(`PASS qwerty`),
				s(`\+OK welcome`),
				c(`STAT`),
				s(`\+OK 3 16`),
				c(`LIST`),
				s(`\+OK 3 messages \(.+ octets\)`),
				// s(`1 5`),
				// s(`2 6`),
				// s(`3 16`),
				// s(`\.`),
				c(`LIST 1`),
				s(`\+OK 1 6`),
				c(`RETR 1`),
				s(`\+OK 6 octets`),
				c(`NOOP`),
				s(`\+OK`),
				c(`NOOP asd`),
				s(`\+OK`),

				c(`UIDL`),
				s(`\+OK 3 messages \(.+ octets\)`),
				// s(`1 foo`),
				// s(`2 bar`),
				// s(`3 foobarty`),
				// s(`\.`),
				c(`UIDL 1`),
				s(`\+OK 1 bar`),
				c(`LIST 1`),
				s(`\+OK 1 6`),
				c(`UIDL abc`),
				s(`-ERR invalid argument`),
				c(`LIST abc`),
				s(`-ERR invalid argument`),
				c(`USER`),
				s(`-ERR malformed command`),
				c(`PASS`),
				s(`-ERR malformed command`),
				c(`QUIT`),
				s(`\+OK bye`),
			},
			fail: false,
		},
		{
			name: "test retrive",
			auth: dummy,
			cmd: []fmt.Stringer{
				s(`\+OK Gpop ready for requests from .*`),
				c(`USER john`),
				s(`\+OK send PASS`),
				c(`PASS qwerty`),
				s(`\+OK welcome`),
				c(`RETR 1`),
				s(`\+OK . octets`),
				c(`RETR x`),
				s(`-ERR invalid argument`),
				c(`RETR 1024`),
				s(`-ERR unknown message`),
				c(`QUIT`),
				s(`\+OK bye`),
			},
			fail: false,
		},
		{
			name: "test deletes",
			auth: dummy,
			cmd: []fmt.Stringer{
				s(`\+OK Gpop ready for requests from .*`),
				c(`USER john`),
				s(`\+OK send PASS`),
				c(`PASS qwerty`),
				s(`\+OK welcome`),
				c(`STAT`),
				s(`\+OK 3 16`),
				c(`DELE`),
				s(`-ERR invalid argument`),
				c(`DELE 2`),
				s(`\+OK message 2 deleted`),
				c(`DELE x`),
				s(`-ERR invalid argument`),
				c(`DELE a b`),
				s(`-ERR invalid argument`),
				c(`DELE 4`),
				s(`-ERR unknown message`),
				c(`RSET`),
				s(`-ERR invalid argument`),
				c(`RSET 123`),
				s(`-ERR RSET _what_\?`),
				c(`RSET 1`),
				s(`-ERR RSET _what_\?`),
				c(`DELE 3`),
				s(`\+OK message 3 deleted`),
				c(`RSET 3`),
				s(`\+OK`),
				c(`RSET 2`),
				s(`\+OK`),
				c(`RSET 1`),
				s(`-ERR RSET _what_\?`),
				c(`QUIT`),
				s(`\+OK bye`),
			},
			fail: false,
		},
		{
			name: "failing list",
			auth: &auth{
				m: &listErrorMaildrop{},
			},
			cmd: []fmt.Stringer{
				s(`\+OK Gpop ready for requests from .*`),
				c(`USER john`),
				s(`\+OK send PASS`),
				c(`PASS qwerty`),
				s(`-ERR maildrop locked`),
			},
			fail: false,
		},
		{
			name: "failing maildrop",
			auth: &auth{
				m: &errorMaildrop{
					messages: messages,
				},
			},
			cmd: []fmt.Stringer{
				s(`\+OK Gpop ready for requests from .*`),
				c(`USER john`),
				s(`\+OK send PASS`),
				c(`PASS qwerty`),
				s(`\+OK welcome`),
				c(`RETR 1`),
				s(`-ERR no such message`),
				c(`RETR 2`),
				s(`-ERR no such message`),
				c(`RETR 3`),
				s(`-ERR no such message`),
				c(`DELE 3`),
				s(`\+OK message 3 deleted`),
				c(`QUIT`),
				s(`-ERR oops`),
			},
			fail: false,
		},
	}

	// for n, tst := range tests {
	// 	var data []byte
	// 	for _, cmd := range tst.cmd {
	// 		switch cmd.(type) {
	// 		case c:
	// 			fmt.Print(cmd)
	// 			data = append(data, []byte(cmd.String())...)
	// 		}
	// 	}
	// 	if err := ioutil.WriteFile(fmt.Sprintf("corpus/%d", n), data, 0644); err != nil {
	// 		log.Fatalln(err)
	// 	}
	// }

	ln, err := net.ListenTCP("tcp", nil)
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}

	log.SetOutput(ioutil.Discard)

	server := &Server{Auth: dummy}
	done := make(chan struct{})
	go func() {
		if err := server.Serve(ln); err != nil {
			t.Fatalf("server.Serve failed: %v", err)
		}
		close(done)
	}()
	defer server.Close()

tests:
	for _, tst := range tests {
		exp, err := SpawnConnection(ln.Addr(), timeout, done)
		if err != nil {
			t.Errorf("%s: SpawnConnection failed: %v", tst.name, err)
			continue
		}
		defer exp.Close()

		for _, cmd := range tst.cmd {
			server.Auth = tst.auth
			switch cmd.(type) {
			case s:
				re, err := regexp.Compile(cmd.String())
				if err != nil {
					t.Errorf("%s: regexp.Compile failed: `%s` %v", tst.name, cmd, err)
					continue tests
				}
				out, _, err := exp.Expect(re, timeout)
				if got, want := err == nil, !tst.fail; got != want {
					t.Errorf("%s: Expect(%q,%v) = %t want: %t , err: %v, out: %q", tst.name, re.String(), 0, got, want, err, out)
					continue tests
				}

			case c:
				if err := exp.Send(cmd.String()); err != nil {
					t.Errorf("%s, exp.Send failed: `%s` %v", tst.name, cmd, err)
					continue tests
				}
			}
		}
	}
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

type errorMaildrop struct {
	messages map[string]string
}

func (m *errorMaildrop) List() (sizes map[string]int, err error) {
	sizes = make(map[string]int)
	for k, v := range m.messages {
		sizes[k] = len(v)
	}

	return sizes, nil
}

func (m *errorMaildrop) Get(key string, message io.Writer) (err error) {
	return errors.New("get error")
}

func (m *errorMaildrop) Delete(key string) (err error) {
	return errors.New("delete error")
}

type listErrorMaildrop struct{}

func (m *listErrorMaildrop) List() (sizes map[string]int, err error) {
	return nil, errors.New("list error")
}

func (m *listErrorMaildrop) Get(key string, message io.Writer) (err error) {
	return errors.New("get error")

}

func (m *listErrorMaildrop) Delete(key string) (err error) {
	return errors.New("delete error")
}

func SpawnConnection(addr net.Addr, timeout time.Duration, done chan struct{}) (*expect.GExpect, error) {
	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		return nil, err
	}
	exp, _, err := expect.SpawnGeneric(&expect.GenOptions{
		In:  conn,
		Out: conn,
		Wait: func() error {
			<-done
			return nil
		},
		Close: func() error {
			return conn.Close()
		},
		Check: func() bool { return true },
	}, timeout)
	if err != nil {
		return nil, err
	}

	return exp, nil
}

type c string

func (c c) String() string {
	return string(c) + "\r\n"
}

type s string

func (s s) String() string {
	return string(s)
}
