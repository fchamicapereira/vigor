. ./config.sh

echo "syncing scripts"
. ./sync-scripts.sh

echo "Provisioning tester pktgen for loopback scenario"
ssh $TESTER_HOST 'sudo bash ~/scripts/dpdk-setup-tester-lb.sh'
