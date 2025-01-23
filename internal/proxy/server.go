package proxy

import (
	"bufio"
	"context"
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
		return err
	}
	defer listener.Close()

	s.logger.Info("Proxy server listening", zap.String("addr", addr))

	for {
		conn, err := listener.Accept()
		if err != nil {
			s.logger.Error("Accept error", zap.Error(err))
			continue
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

	s.logger.Debug("Request received",
		zap.String("host", req.Host),
		zap.String("method", req.Method))

	host, port, err := net.SplitHostPort(req.Host)
	if err != nil {
		host = req.Host
		port = "443"
	}

	ip, err := s.resolver.ResolveHost(host)
	if err != nil {
		s.logger.Error("DNS resolution failed", zap.Error(err))
		return
	}

	serverConn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), 5*time.Second)
	if err != nil {
		s.logger.Error("Dial error", zap.Error(err))
		return
	}
	defer serverConn.Close()

	if req.Method == http.MethodConnect {
		_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	}

	go io.Copy(serverConn, clientConn)
	io.Copy(clientConn, serverConn)
}
