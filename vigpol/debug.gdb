set pagination off
set width 0
set height 0
set verbose off

run --vdev "net_tap0,iface=test_wan" \
        --vdev "net_tap1,iface=test_lan" \
        --no-shconf -- \
        --lan 1 \
        --wan 0 \
        --rate 12500 \
        --burst 500000 \
        --capacity 65536
