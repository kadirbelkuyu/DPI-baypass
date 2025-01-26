package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/kadirbelkuyu/DPI-bypass/internal/dns"
	"go.uber.org/zap"
)

const (
	BufferSize = 1024
	scopeProxy = "PROXY"
)

type Server struct {
	addr     string
	port     int
	logger   *zap.Logger
	resolver *dns.Resolver
}

func NewServer(addr string, port int, logger *zap.Logger) *Server {
	return &Server{
		addr:     addr,
		port:     port,
		logger:   logger,
		resolver: dns.NewResolver(),
	}
}

func (s *Server) Start(ctx context.Context) error {
	addr := net.JoinHostPort(s.addr, strconv.Itoa(s.port))
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to start proxy server: %v", err)
	}
	defer listener.Close()

	s.logger.Info("Proxy server listening", zap.String("addr", addr))

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				s.logger.Error("Failed to accept connection", zap.Error(err))
				continue
			}
		}

		go s.handleConnection(ctx, conn)
	}
}

func (s *Server) resolveHost(host string) (string, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", "8.8.8.8:53") // Google DNS
		},
	}

	var ips []net.IP
	var err error
	for i := 0; i < 3; i++ {
		ips, err = resolver.LookupIP(context.Background(), "ip", host)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if err != nil {
		return "", err
	}
	return ips[0].String(), nil
}

func (s *Server) handleConnection(ctx context.Context, clientConn net.Conn) {
	defer clientConn.Close()

	req, err := http.ReadRequest(bufio.NewReader(clientConn))
	if err != nil {
		s.logger.Error("Read request error", zap.Error(err))
		return
	}

	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	ip, err := s.resolveHostWithFallback(host)
	if err != nil {
		s.logger.Error("DNS resolution failed", zap.Error(err))
		return
	}

	port := "80"
	if req.Method == http.MethodConnect {
		port = "443"
	}

	serverConn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), 10*time.Second)
	if err != nil {
		s.logger.Error("Dial error", zap.Error(err))
		return
	}
	defer serverConn.Close()

	if req.Method == http.MethodConnect {
		clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	} else {
		req.Write(serverConn)
	}

	// Bidirectional copy with larger buffer
	errChan := make(chan error, 2)
	go func() {
		buf := make([]byte, 65536)
		_, err := io.CopyBuffer(serverConn, clientConn, buf)
		errChan <- err
	}()

	go func() {
		buf := make([]byte, 65536)
		_, err := io.CopyBuffer(clientConn, serverConn, buf)
		errChan <- err
	}()

	<-errChan
}

func (s *Server) resolveHostWithFallback(host string) (string, error) {
	// Try built-in resolver first
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}

	// Try custom resolver
	ip, err := s.resolver.ResolveHost(host)
	if err == nil {
		return ip, nil
	}

	// Fallback to system resolver
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("failed to resolve %s: %v", host, err)
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("no IP addresses found for %s", host)
	}

	return ips[0].String(), nil
}
