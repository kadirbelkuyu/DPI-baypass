
#!/bin/bash
PF_CONF="pf.conf"

case "$1" in
  start)
    sudo pfctl -ef "$PF_CONF"
    ;;
  stop)
    sudo pfctl -d
    ;;
  *)
    echo "Usage: $0 {start|stop}"
    exit 1
esac