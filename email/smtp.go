package email

// SMTP client that assumes modern SMTP server with TLS and AUTH PLAIN LOGIN extensions.

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/textproto"
	"slices"
	"strings"
)

type ClientError string

const (
	UnsupportedServer  ClientError = "Unsupported server"
	InvalidCredentials ClientError = "Invalid credentials"
)

func (err ClientError) Error() string {
	return string(err)
}

type Client struct {
	// `net/textproto` implements helpers for text-based protocols like SMTP.
	// Typically, client sends `COMMAND
	Text       *textproto.Conn
	Conn       net.Conn
	ServerName string
	Auth       []string
	LocalName  string
	DidHello   bool
}

type Auth struct {
	Username string
	Password string
}

func Dial(addr string) (*Client, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	host, _, _ := net.SplitHostPort(addr)
	return NewClient(conn, host)
}

func NewClient(conn net.Conn, host string) (*Client, error) {
	text := textproto.NewConn(conn)
	_, _, err := text.ReadResponse(220)
	if err != nil {
		text.Close()
		return nil, err
	}
	c := &Client{Text: text, Conn: conn, ServerName: host, LocalName: "localhost"}
	return c, nil
}

func (c *Client) Close() error {
	return c.Text.Close()
}

func (c *Client) Cmd(expectCode int, format string, args ...any) (int, string, error) {
	id, err := c.Text.Cmd(format, args...)
	if err != nil {
		return 0, "", err
	}
	// Block until we receive the appropriate response, i.e., we get back
	// `CODE STATUS ID` and the id matches.
	//
	// `net/textproto` internally maintains
	c.Text.StartResponse(id)
	defer c.Text.EndResponse(id)
	code, msg, err := c.Text.ReadResponse(expectCode)
	return code, msg, err
}

func (c *Client) Ehlo() (string, error) {
	_, msg, err := c.Cmd(250, "EHLO %s", c.LocalName)
	if err != nil {
		return "", err
	}

	return msg, nil
}

func (c *Client) Quit() error {
	_, _, err := c.Cmd(250, "QUIT")
	if err != nil {
		return err
	}
	return c.Text.Close()
}

func (c *Client) StartTLS(config *tls.Config) error {
	_, _, err := c.Cmd(220, "STARTTLS")
	if err != nil {
		return err
	}
	// Upgrade from just TCP to TLS.
	c.Conn = tls.Client(c.Conn, config)
	c.Text = textproto.NewConn(c.Conn)
	// Try sending EHLO again, just to test out the connection.
	_, err = c.Ehlo()
	return err
}

func (c *Client) PerformAuth(auth Auth) error {
	data := fmt.Sprintf("\x00%s\x00%s", auth.Username, auth.Password)
	encoded := base64.StdEncoding.EncodeToString([]byte(data))
	_, _, err := c.Cmd(235, "AUTH PLAIN %s", encoded)
	if err != nil {
		return InvalidCredentials
	}
	return nil
}

func SendMail(addr string, auth Auth, from string, to []string, msg []byte) error {
	c, err := Dial(addr)
	if err != nil {
		return err
	}
	defer c.Close()

	// Now, try sending EHLO and making sure we can support this server.
	ehlo, err := c.Ehlo()
	if err != nil {
		return err
	}
	extensions := strings.Split(ehlo, "\n")
	// Sending EHLO will return a list of extensions, we're interested in "TLS" and
	// "AUTH PLAIN LOGIN".
	if !slices.Contains(extensions, "STARTTLS") ||
		!slices.Contains(extensions, "AUTH PLAIN LOGIN") ||
		!slices.Contains(extensions, "8BITMIME") {
		return UnsupportedServer
	}

	// Now, try upgrading to TLS.
	tlsConfig := &tls.Config{ServerName: c.ServerName}
	err = c.StartTLS(tlsConfig)
	if err != nil {
		return err
	}

	// Now, try authenticating ourselves.
	err = c.PerformAuth(auth)
	if err != nil {
		return err
	}

	// Now, try sending the email.
	// 8BITMIME allows us to send bytes with the high bit set.
	_, _, err = c.Cmd(250, "MAIL FROM:<%s> BODY=8BITMIME", from)
	if err != nil {
		return err
	}
	for _, addr := range to {
		_, _, err := c.Cmd(25, "RCPT TO:<%s>", addr)
		if err != nil {
			return err
		}
	}
	_, _, err = c.Cmd(354, "DATA")
	if err != nil {
		return err
	}
	// SMTP uses dot-stuffing. A line with just a dot indicates that the message is finished;
	// `DotWriter` just makes sure that ones within the message are escaped if you will.
	w := c.Text.DotWriter()
	_, err = w.Write(msg)
	if err != nil {
		return err
	}
	err = w.Close()
	if err != nil {
		return err
	}

	return c.Quit()
}
