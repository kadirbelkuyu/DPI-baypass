package dns

import (
    "context"
    "net"
    "time"
    "fmt"
)

type Resolver struct {
    servers []string
    timeout time.Duration
}

func NewResolver() *Resolver {
    return &Resolver{
        servers: []string{
            "1.1.1.1:53",
            "1.0.0.1:53",
            "8.8.8.8:53",
            "8.8.4.4:53",
        },
        timeout: 5 * time.Second, 
    }
}

func (r *Resolver) ResolveHost(host string) (string, error) {
    if net.ParseIP(host) != nil {
        return host, nil
    }

    for _, server := range r.servers {
        ip, err := r.resolveWithServer(host, server)
        if err == nil {
            return ip, nil
        }
    }

    return "", fmt.Errorf("all DNS servers failed for %s", host)
}

func (r *Resolver) resolveWithServer(host, server string) (string, error) {
    ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
    defer cancel()

    resolver := &net.Resolver{
        PreferGo: true,
        Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
            d := net.Dialer{Timeout: r.timeout}
            return d.DialContext(ctx, "udp", server)
        },
    }

    ips, err := resolver.LookupIPAddr(ctx, host)
    if err != nil {
        return "", err
    }

    if len(ips) == 0 {
        return "", fmt.Errorf("no IPs found")
    }

    return ips[0].String(), nil
}