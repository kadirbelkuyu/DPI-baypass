package dns

import (
    "context"
    "net"
    "time"
)

type Resolver struct {
    servers []string
    timeout time.Duration
}

func NewResolver() *Resolver {
    return &Resolver{
        servers: []string{
            "1.1.1.1:53",      // Cloudflare primary (usually more reliable)
            "8.8.8.8:53",      // Google primary
            "1.0.0.1:53",      // Cloudflare secondary
            "8.8.4.4:53",      // Google secondary
        },
        timeout: 5 * time.Second, // Increased timeout
    }
}

func (r *Resolver) ResolveHost(host string) (string, error) {
    // Check if input is already an IP
    if net.ParseIP(host) != nil {
        return host, nil
    }

    resolver := &net.Resolver{
        PreferGo: true,
        Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
            d := net.Dialer{
                Timeout: r.timeout,
            }
            for _, server := range r.servers {
                conn, err := d.DialContext(ctx, "udp", server)
                if err == nil {
                    return conn, nil
                }
            }
            return nil, net.UnknownNetworkError("all DNS servers failed")
        },
    }
    
    ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
    defer cancel()
    
    ips, err := resolver.LookupIPAddr(ctx, host)
    if err != nil {
        return "", err
    }
    
    if len(ips) == 0 {
        return "", net.UnknownNetworkError("no IP addresses found")
    }
    
    return ips[0].String(), nil
}
