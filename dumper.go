package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

func hackyDialWithDialer(dialer *net.Dialer, network, addr string, config *tls.Config) (*tls.Conn, error) {
	// We want the Timeout and Deadline values from dialer to cover the
	// whole process: TCP connection and TLS handshake. This means that we
	// also need to start our own timers now.
	timeout := dialer.Timeout
	if !dialer.Deadline.IsZero() {
		deadlineTimeout := time.Until(dialer.Deadline)
		if timeout == 0 || deadlineTimeout < timeout {
			timeout = deadlineTimeout
		}
	}
	var errChannel chan error
	if timeout != 0 {
		errChannel = make(chan error, 2)
		timer := time.AfterFunc(timeout, func() {
			errChannel <- fmt.Errorf("Timeout fuck")
		})
		defer timer.Stop()
	}
	rawConn, err := dialer.Dial(network, addr)
	if err != nil {
		return tls.Client(rawConn, config), err
	}
	colonPos := strings.LastIndex(addr, ":")
	if colonPos == -1 {
		colonPos = len(addr)
	}
	hostname := addr[:colonPos]
	if config == nil {
		//config = *tls.Config{} // defaultConfig()
	}
	// If no ServerName is set, infer the ServerName
	// from the hostname we're connecting to.
	if config.ServerName == "" {
		// Make a copy to avoid polluting argument or default.
		c := config.Clone()
		c.ServerName = hostname
		config = c
	}
	conn := tls.Client(rawConn, config)
	if timeout == 0 {
		err = conn.Handshake()
	} else {
		go func() {
			errChannel <- conn.Handshake()
		}()
		err = <-errChannel
	}
	if err != nil {
		rawConn.Close()
		return conn, err
	}
	return conn, nil
}

func worker(jobChan <-chan string, resChan chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	var host string
	var port string

	config := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	}
	config.VerifyPeerCertificate = func(certificates [][]byte, _ [][]*x509.Certificate) error {
		certs := make([]*x509.Certificate, len(certificates))
		for i, asn1Data := range certificates {
			cert, err := x509.ParseCertificate(asn1Data)
			if err != nil {
				return errors.New("tls: failed to parse certificate from server: " + err.Error())
			}
			certs[i] = cert
		}
		opts := x509.VerifyOptions{
			Roots:         config.RootCAs, // On the server side, use config.ClientCAs.
			DNSName:       config.ServerName,
			Intermediates: x509.NewCertPool(),
		}
		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}
		_, err := certs[0].Verify(opts)
		// if strings.Contains(err.Error(), "certificate has expired or is not yet valid") {
		// 	return nil
		// }
		return err
	}

	for {
		job, ok := <-jobChan
		if !ok {
			return
		}

		tmp := strings.Split(job, ",")
		host = tmp[0]
		port = "443" // Default tls port
		if len(tmp) > 1 {
			port = tmp[1]
		}
		conn, err := hackyDialWithDialer(&net.Dialer{
			Timeout: time.Second * 5,
		}, "tcp", host+":"+port, config)
		if err != nil {
			// log.Println(err)
			continue
		}
		// conn.Handshake()
		certChain := [][]byte{}
		if conn.ConnectionState().PeerCertificates == nil {
			// log.Println("no certs?")
			continue
		}
		x := conn.ConnectionState().PeerCertificates[:]
		// x = make([]*x509.Certificate, l)
		for _, i := range x {
			certChain = append(certChain, i.Raw)
		}
		cn := x[0].Subject.CommonName
		config.ServerName = cn
		conn.Close()
		valid := config.VerifyPeerCertificate(certChain, [][]*x509.Certificate{})
		if valid == nil { //invalid cert
			// log.Println(valid)
			resChan <- fmt.Sprintf("%s,%s,%s", cn, host, port)
			// continue
		}
	}

}
func main() {
	workers := flag.Int("t", 32, "numbers of threads")
	flag.Parse()

	scanner := bufio.NewScanner(os.Stdin)
	jobChan := make(chan string)
	resChan := make(chan string)
	done := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(*workers)

	go func() {
		wg.Wait()
		close(done)
	}()

	for i := 0; i < *workers; i++ {
		go worker(jobChan, resChan, &wg)
	}

	go func() {
		for scanner.Scan() {
			jobChan <- scanner.Text()
		}
		if err := scanner.Err(); err != nil {
			log.Println(err)
		}
		close(jobChan)
	}()

	for {
		select {
		case <-done:
			return
		case res := <-resChan:
			fmt.Println(res)
		}
	}
	return
}
