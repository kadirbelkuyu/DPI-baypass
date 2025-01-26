package dns

import (
    "context"
    "net"
    "sync"
    "time"
    "fmt"
)

type cacheEntry struct {
    ip        string
    expiresAt time.Time
}

type Resolver struct {
    servers []string
    timeout time.Duration
    retries int
    cache   sync.Map
    ttl     time.Duration
}

func NewResolver() *Resolver {
    return &Resolver{
        servers: []string{
            "1.1.1.1:53",      // Cloudflare
            "8.8.8.8:53",      // Google
            "9.9.9.9:53",      // Quad9
            "208.67.222.222:53", // OpenDNS
            "77.88.8.8:53",      // Yandex
            "176.103.130.130:53", // AdGuard
            "8.26.56.26:53",     // Comodo
            "185.228.168.9:53",  // Clean Browsing
        },
        timeout: 5 * time.Second,
        retries: 3,
        ttl:     5 * time.Minute,
    }
}

func (r *Resolver) ResolveHost(host string) (string, error) {
    // Check cache first
    if entry, ok := r.cache.Load(host); ok {
        if ce, ok := entry.(cacheEntry); ok && time.Now().Before(ce.expiresAt) {
            return ce.ip, nil
        }
        r.cache.Delete(host)
    }

    // Try direct IP first
    if ip := net.ParseIP(host); ip != nil {
        return host, nil
    }

    // Try each server with retries
    var lastErr error
    for i := 0; i < r.retries; i++ {
        for _, server := range r.servers {
            ip, err := r.resolveWithServer(host, server)
            if err == nil {
                // Cache successful resolution
                r.cache.Store(host, cacheEntry{
                    ip:        ip,
                    expiresAt: time.Now().Add(r.ttl),
                })
                return ip, nil
            }
            lastErr = err
        }
        time.Sleep(time.Duration(i+1) * 100 * time.Millisecond)
    }

    return "", fmt.Errorf("failed to resolve %s after %d retries: %v", host, r.retries, lastErr)
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