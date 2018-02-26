#!/bin/bash -x

function Usage() {
	echo "1st arg disk file name for target"
	echo "2nd arg fio config file"
	exit 1
}

if [ $# -lt 2 ]; then
	Usage
fi

DISK1=$1
FIO_CONFIG=$2

function Cmd_present() {
	command -v $1 2>&1 > /dev/null
	if [ ! $? -eq 0 ]; then
		echo "Command $1 not present"
		exit $?
	fi
}

# Check for all the to be used commands
Cmd_present tgtd
Cmd_present tgtadm
Cmd_present curl
Cmd_present iscsiadm
Cmd_present fio

if [ -f "$DISK1" ]; then
	echo "File $DISK1 already present."
	exit 1
fi

echo "Creating 1G file to be exported as LUN"
#fallocate -l 1G $DISK1
dd if=/dev/zero of=$DISK1 bs=1G count=1

if [ ! $? -eq 0 ]; then
	echo "File creation of $DISK1 failed"
	exit $?
fi

# Start the tgtd
./tgtd

if [ ! $? -eq 0 ]; then
	echo "Starting tgtd failed"
	exit $?
fi

# Create new VM through REST API
curl  -s -XPOST 'http://localhost:1984/new_vm/1' \
	-d '{"vmid":"1","TargetID":"1","TargetName":"disk1"}' \
	-H 'Content-Type: application/json' 2>&1 > /dev/null

if [ ! $? -eq 0 ]; then
	echo "Create new VM REST API failed"
	exit $?
else
	echo "New VM with vmid 1, rest api successful"
fi

# Create new VMDK through REST API
curl  -s -XPOST 'http://localhost:1984/vm/1/new_vmdk/1' \
	-d '{"TargetID":"1","LunID":"1","DevPath":"/var/tmp/iscsi-disk1","VmID":"1","VmdkID":"1","BlockSize":"4096","Compression":{"Enabled":"false"},"Encryption":{"Enabled":"false"},"RamCache":{"Enabled":"true","MemoryInMB":"1024"},"FileCache":{"Enabled":"false"},"SuccessHandler":{"Enabled":"true"}}' \
	-H'Content-Type: application/json' 2>&1 > /dev/null

if [ ! $? -eq 0 ]; then
	echo "Create new VMDK REST API failed"
	exit $?
else
	echo "New VMDK with vmdkid 1, rest api successful"
fi

# Make the target discoverable
tgtadm --lld iscsi --op bind --mode target --tid 1 -I ALL

if [ ! $? -eq 0 ]; then
	echo "Target discoverable command failed"
	exit $?
else
	echo "Target with tid 1 is now discoverable"
fi

# Login through iscsi on this target
iscsiadm --mode node --targetname disk1 --portal 127.0.0.1:3260 --login

if [ ! $? -eq 0 ]; then
	echo "iscsi login to target tid 1 failed"
	exit $?
else
	echo "iscsi login to target tid 1 successful"
fi

# run fio
FIO_PATH=$HOME/fio_$$

mkdir $FIO_PATH

if [ ! $? -eq 0 ]; then
	echo "mkdir $FIO_PATH failed"
	exit $?
else
	echo "FIO logs with be at $FIO_PATH"
fi

cd $FIO_PATH

fio $HOME/config.fio

if [ ! $? -eq 0 ]; then
	echo "fio run failed"
else
	echo "fio run succeeded"
fi


