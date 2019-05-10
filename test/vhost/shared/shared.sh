#!/usr/bin/env bash

set -e

testdir=$(readlink -f $(dirname $0))
rootdir=$(readlink -f $testdir/../../..)
source $rootdir/test/common/autotest_common.sh
source $rootdir/test/vhost/common.sh

PLUGIN_DIR=$rootdir/examples/bdev/fio_plugin
FIO_PATH="/usr/src/fio"
rpc_py="$SPDK_BUILD_DIR/scripts/rpc.py -s $(get_vhost_dir)/rpc.sock"

function run_spdk_fio() {
	LD_PRELOAD=$PLUGIN_DIR/fio_plugin $FIO_PATH/fio --ioengine=spdk_bdev \
	"$rootdir/test/vhost/common/fio_jobs/default_initiator.job" --runtime=10 --rw=randrw \
	--spdk_mem=1024 --spdk_single_seg=1 --spdk_conf=$testdir/bdev.conf "$@"
}

trap 'error_exit "${FUNCNAME}" "${LINENO}"' ERR SIGTERM SIGABRT

spdk_vhost_run

$rpc_py construct_malloc_bdev -b Malloc 124 4096
$rpc_py construct_vhost_blk_controller Malloc.0 Malloc

run_spdk_fio --size=50% --offset=0 --filename=VirtioBlk0 &
run_fio_pid=$!
sleep 1
run_spdk_fio --size=50% --offset=50% --filename=VirtioBlk0
wait $run_fio_pid
spdk_vhost_kill
