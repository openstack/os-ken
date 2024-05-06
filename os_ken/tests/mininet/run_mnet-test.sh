#!/bin/sh

RUN_DIR=`dirname $0`
CMD_NAME=`basename $0 .sh`
CMD_PATH=`readlink -f $0`
CMD_DIR=`dirname $CMD_PATH`
DUMP_SEC=10
DUMP_DELAY=2
DUMP_DIR=/tmp/test-mn/dump
TEST_LIST=
TEST_SUFFIX=.mn
MN_PRE_FILE=/tmp/test-mn/mn-pre
MN_POST_FILE=/tmp/test-mn/mn-post
PKG_LIST="tshark tcpreplay mz"
RTN=0

# usage
usage() {
    echo "Usage: $0 [OPTION] [TEST DIR or FILE]..."
    echo ""
    echo "Run OSKen's test in mininet"
    echo "ex.) $ $0 l2 l3/icmp/ICMP_ping.mn"
    echo ""
    echo "Options:"
    echo "  -h, --help  show this help message and exit"
    exit 0
}

# set default environment
set_env() {
    POST_IF=h1-eth0
    DUMP_HOST=h2
    DUMP_IF=h2-eth0
    TEST_NAME=
    DUMP_FILE=
    OSKEN_APP=
    OSKEN_LOG=
    PCAP_MZ=
    PCAP_FILE=
    PCAP_FILTER=
    PCAP_COM=
    CACHE_HIT=
}

# making mininet-test-pre-file
mn_pre() {
    exec 3>&1
    exec >$MN_PRE_FILE
    echo "sh echo '----------------------------------'"
    echo "sh echo '(pre) mininet topology dump.'"
    echo "sh echo '----------------------------------'"
    echo "dump"
    echo "net"
    echo "sh echo '----------------------------------'"
    echo "sh echo '(pre) tshark start.'"
    echo "sh echo '----------------------------------'"
    echo "$DUMP_HOST tshark -i $DUMP_IF -a duration:$DUMP_SEC -w $DUMP_FILE &"
    echo "sh sleep $DUMP_DELAY"
    echo "sh echo '----------------------------------'"
    exec 1>&3
}

# making mininet-test-post-file
mn_post() {
    exec 3>&1
    exec >$MN_POST_FILE
    echo "sh ovs-vsctl del-controller s1"
    echo "sh ovs-vsctl set bridge s1 protocols='[OpenFlow10,OpenFlow12]'"
    echo "sh ovs-vsctl set-controller s1 tcp:127.0.0.1"
    echo "sh echo '----------------------------------'"
    echo "sh echo '(post) packet sending...'"
    echo "sh echo '----------------------------------'"
    echo $PCAP_COM
    echo "sh sleep 1"
    echo "sh echo '----------------------------------'"
    echo "sh echo '(post) dump flows.'"
    echo "sh echo '----------------------------------'"
    echo "sh ovs-ofctl dump-flows s1"
    echo "sh echo '----------------------------------'"
    exec 1>&3
}

# ovs cache-hit incremental check
ovs_cache_hit() {
    expr `sudo ovs-dpctl show|sed -n 's|lookups: hit:||gp'|awk '{print $1}'` - ${1:-0}
}

# starting osken-manager
run_osken() {
    ERRSTAT=0
    ERRTAG="run_osken() :"

    echo "Inf: OSKEN_APP=$OSKEN_APP"
    echo "Inf: osken-manager starting..."
    osken-manager --verbose $OSKEN_APP 2>$DUMP_DIR/$OSKEN_LOG &
    PID_OSKEN=$!
    sleep 1
    [ -d /proc/$PID_OSKEN ] || err $ERRTAG "failed to start osken-manager."

    return $ERRSTAT
}

# starting mininet and test-script
run_mn() {
    echo "Info: mininet starting..."
    sudo mn --mac --test none --pre $MN_PRE_FILE --post $MN_POST_FILE \
            --controller remote 127.0.0.1
}

# cleaning after mininet
clean_mn() {
    wait_osken
    rm -f $MN_PRE_FILE $MN_POST_FILE
}

# check packet and chache-hit
check() {
    PACKET=`tshark -r $DUMP_FILE -R "$PCAP_FILTER" 2>/dev/null`
    if [ ! "$PACKET" ]; then
        RESULT=NG
        REASON="(unmatched packet. please check $DUMP_FILE)"
    elif [ "$CACHE_HIT" ] && [ `ovs_cache_hit $CACHE_HIT` -eq 0 ]; then
        RESULT=NG
        REASON="(ovs cache hit miss.)"
    else
        RESULT=OK; REASON=
    fi
    echo
    echo "TEST ${TEST_NAME} : $RESULT $REASON"
}

# stoping osken-manager
wait_osken() {
    kill -2 $PID_OSKEN
    wait $PID_OSKEN
}

# test-main
test_mn() {
    DUMP_FILE=$DUMP_DIR/$DUMP_FILE
    touch $DUMP_FILE
    sudo chmod o+w $DUMP_FILE
    [ "$CACHE_HIT" ] && CACHE_HIT=`ovs_cache_hit 0`
    mn_pre
    mn_post
    run_osken; [ $? -ne 0 ] && return 1
    run_mn; [ $? -ne 0 ] && return 1
    check

    return 0
}

err() {
    echo Error: $*
    ERRSTAT=1
}

mnfile_check() {
    test=`basename $1 $TEST_SUFFIX`
    file=`readlink -f $1`
    TEST_DIR=`dirname $file`
    ERRSTAT=0
    ERRTAG="mnfile_check() :"

    # test-file check
    if [ ! -r $file ]; then
        err $ERRTAG "cannot open the file: $file"
        return $ERRSTAT
    fi

    . $file || err $ERRTAG "failed to include $file"

    # parameter check
    [ "$OSKEN_APP" ] || err $ERRTAG: "OSKEN_APP is not defined"
    [ "$PCAP_FILE" -o "$PCAP_MZ" ] || err $ERRTAG: "PCAP_FILE or PCAP_MZ is not defined"
    [ "$PCAP_FILTER" ] || err $ERRTAG "PCAP_FILTER is not defined"
    [ "$TEST_NAME" ] || TEST_NAME=$test
    [ "$DUMP_FILE" ] || DUMP_FILE=$test.dump
    [ "$OSKEN_LOG" ] || OSKEN_LOG=osken-manager.$test.log
    [ $ERRSTAT -ne 0 ] && return $ERRSTAT

    # pcap check (pcap-file or mz-option)
    if [ "$PCAP_FILE" ]; then
        PCAP_FILE=$TEST_DIR/$PCAP_FILE
        [ -r $PCAP_FILE ] || err $ERRTAG "PCAP_FILE[$PCAP_FILE] cannot read"
        PCAP_COM="h1 tcpreplay -l 3 -i $POST_IF $PCAP_FILE"
    elif [ "$PCAP_MZ" ]; then
        PCAP_COM="h1 mz $POST_IF $PCAP_MZ"
    fi
    [ $ERRSTAT -ne 0 ] && return $ERRSTAT

    # osken-app check
    [ -r $TEST_DIR/$OSKEN_APP -o -r $TEST_DIR/${OSKEN_APP}.py ] && OSKEN_APP=$TEST_DIR/$OSKEN_APP

    return $ERRSTAT
}

arg_check() {
    ARGLIST=
    ERRTAG="argcheck() :"

    case "$1" in
        -h|--help) usage;;
    esac

    if [ $# -ne 0 ]; then
        ARGLIST=$*
    else
        ARGLIST=`find . -type f -name "*$TEST_SUFFIX"`
    fi

    for arg in $ARGLIST; do
        if [ -d $arg ]; then
            file=`find $arg -type f -name "*$TEST_SUFFIX"`
        elif [ -f $arg ]; then
            file=$arg
        else
            err $ERRTAG "$arg is not found"
            file=
        fi

        TEST_LIST="$TEST_LIST $file"
    done
}

pkg_check() {
    no_pkg=
    for pkg in $PKG_LIST; do
        [ ! `which $pkg` ] && no_pkg="$no_pkg $pkg"
    done
    for pkg in $no_pkg; do
        echo "Error: Package [ $pkg ] is not found. Please install."
    done
    [ "$no_pkg" ] && exit 1
}

### main
[ -d $DUMP_DIR ] || mkdir -p $DUMP_DIR

pkg_check
arg_check $*
echo "\n---------- test target ----------"
for testfile in $TEST_LIST; do echo $testfile; done

count=0
for testfile in $TEST_LIST; do
    echo "\n---------- test [$testfile] start ----------"
    set_env
    mnfile_check $testfile && test_mn
    case $? in
        0) msg="finished : $RESULT" ;;
        *) msg="skipped with error"; RESULT="skip" ;;
    esac
    eval RESULT_${count}=\$RESULT
    eval REASON_${count}=\$REASON
    count=`expr $count + 1`
    num=`eval echo \\${num_$RESULT:-0}`
    eval num_${RESULT}=`expr $num + 1`
    [ "$RESULT" != "OK" ] && RTN=1
    clean_mn
    echo "\n---------- test [$testfile] $msg ----------"
done

# output summary results
echo "\n---------- test results ----------"
count=0
for testfile in $TEST_LIST; do
    eval echo \$testfile : \$RESULT_${count} \$REASON_${count}
    count=`expr $count + 1`
done
echo "----------------------------------"
echo "Ran $count tests. Result: ${num_OK:+OK=}$num_OK ${num_NG:+NG=}$num_NG ${num_skip:+skip=}$num_skip"

exit $RTN
