#!/bin/sh
#
# Copyright (C) 2012 Roi Dayan <roid@mellanox.com>
#


DIR=$(cd `dirname $0`; pwd)
BASE=`cd $DIR/.. ; pwd`
RPMTOP="$BASE/rpmtop"
SPEC="tgtd.spec"
LOG=/tmp/`basename $0`-$$.log

# get branch name
branch=`git branch | grep '^*' | sed 's/^..\(.*\)/\1/'`
# get version tag
version=`git describe --tags --abbrev=0 | sed "s/^v//g"`
# release is number of commits since the version tag
release=`git describe --tags | cut -d- -f2 | tr - _`

if [ "$version" = "$release" ]; then
    # no commits and release can't be empty
    release=0
fi

if [ "$branch" != "master" ]; then
    # if not under master branch include hash tag
    hash=`git rev-parse HEAD | cut -c 1-6`
    release+=".$hash"
fi

echo "Building version: $version-$release"

name=scsi-target-utils-$version-$release
TARBALL=$name.tgz
SRPM=$RPMTOP/SRPMS/$name.src.rpm

echo "Creating rpm build dirs under $RPMTOP"
mkdir -p $RPMTOP/{RPMS,SRPMS,SOURCES,BUILD,SPECS,tmp}
mkdir -p $RPMTOP/tmp/$name

echo "Creating tgz $TARBALL"
cd $BASE
cp -a conf $RPMTOP/tmp/$name
cp -a doc $RPMTOP/tmp/$name
cp -a scripts $RPMTOP/tmp/$name
cp -a usr $RPMTOP/tmp/$name
cp -a README $RPMTOP/tmp/$name
cp -a Makefile $RPMTOP/tmp/$name

tar -czf $RPMTOP/SOURCES/$TARBALL -C $RPMTOP/tmp $name

check() {
    local rc=$?
    local msg="$1"
    if (( rc )); then
        echo $msg
        exit 1
    fi
}

echo "Creating rpm"
sed -r "s/^Version:(\s*).*/Version:\1$version/;s/^Release:(\s*).*/Release:\1$release/" scripts/$SPEC > $RPMTOP/SPECS/$SPEC
rpmbuild -bs --define="_topdir $RPMTOP" $RPMTOP/SPECS/$SPEC
check "Failed to create source rpm."

rpmbuild -bb --define="_topdir $RPMTOP" $RPMTOP/SPECS/$SPEC > $LOG 2>&1
check "Failed to build rpm. LOG: $LOG"
# display created rpm files
grep ^Wrote $LOG

rm -fr $LOG
echo "Done."
