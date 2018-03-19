#!/bin/bash

echo "this is run.sh for tgt" 

# uncomment the below line and comment rest all to aid debug
#tail -F -n0 /etc/hosts

cwd=$(pwd)

echo "build folly start"
cd folly
rm -rf _build
mkdir _build
cd _build
cmake configure .. -DBUILD_SHARED_LIBS=ON
make
make install
echo "build folly complete"

cd $cwd
echo "build CRoaring start"
cd hyc-storage-layer/thirdparty/CRoaring
rm -rf _build
mkdir _build
cd _build
cmake ..
make
make install
echo "build CRoaring complete"

cd $cwd
echo "build restbed start"
cd hyc-storage-layer/thirdparty/restbed
rm -rf _build
mkdir _build
cd _build
cmake -DBUILD_SHARED=YES ..
make
make install
echo "build restbed complete"

cd $cwd
echo "gtest build start"
cd googletest
rm -rf _build
mkdir _build
cd _build
cmake ..
make
make install
echo "gtest build complete"

cd $cwd
echo "storage lib build start"
cd hyc-storage-layer
rm -rf _build
mkdir _build
cd _build
cmake ..
make
make test
make install
echo "storage lib build complete"

cd $cwd
echo "tgt build start"
cd tgt
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/lib/hyc
make 
echo "tgt build complete"

cd $cwd
echo "run.sh for tgt exiting"
