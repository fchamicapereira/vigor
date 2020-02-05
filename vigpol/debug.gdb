set pagination off
set width 0
set height 0
set verbose off

b nf-util.h:109
b nf-util.h:110

run --vdev "net_tap0,iface=test_wan" \
        --vdev "net_tap1,iface=test_lan" \
        --no-shconf -- \
        --lan 1 \
        --wan 0 \
        --rate 12500 \
        --burst 500000 \
        --capacity 65536

set $i = 0
	while($i<32)
    	set $i = $i + 1
		printf "\n\n*** BEFORE chunks_borrowed_num %u\n", chunks_borrowed_num
		c
		printf "*** AFTER  chunks_borrowed_num %u\n", chunks_borrowed_num
		c
	end
end
