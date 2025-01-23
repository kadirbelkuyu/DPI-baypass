#!/bin/bash

case "$1" in
  start)
    iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 8080
    iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8080
    ;;
  stop)
    iptables -t nat -D OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 8080
    iptables -t nat -D OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8080
    ;;
  *)
    echo "Usage: $0 {start|stop}"
    exit 1
esac

exit 0
