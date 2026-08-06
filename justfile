#!/usr/bin/env just --justfile

XDIR := justfile_directory()
EXE := "w3authd"
XEXE := XDIR+'/'+EXE

XARCH := os()+"-"+arch()

clean-assets:
    #!/bin/sh
    rm -rf {{XDIR}}/pkg/server/assets

fetch-assets:
    #!/bin/sh
    ## {{XDIR}}/pkg/server/assets
    mkdir -p {{XDIR}}/pkg/server/assets
    for x in $(grep -v "^#" {{XDIR}}/resource.list); do
        url=${x%%,*}
        sub=${x##*,}
        file=${url##*/}
        [ -f {{XDIR}}/pkg/server/assets/$sub/$file ] || (mkdir -p {{XDIR}}/pkg/server/assets/$sub && cd {{XDIR}}/pkg/server/assets/$sub && wget -c "$url" -O "$file")
    done

run-test: build
    #!/bin/sh
    cd {{XDIR}}/test
    {{XEXE}} -htpasswd {{XDIR}}/test/htpasswd \
        -ldapconfig {{XDIR}}/test/ldap.hcl \
        -templateOverlay {{XDIR}}/test/html

set-drel: inc-level
    #!/bin/bash
    V=$(date '+%Y.%m.')
    V=$V$(cd {{XDIR}} && shtool version -n "{{EXE}}" -l short ./version.txt|cut -f 3 -d.)
    cd {{XDIR}} && just -f justfile set-version "$V"

inc-version:
    #!/bin/bash
    cd {{XDIR}}
    shtool version -n "{{EXE}}" -i v -l txt ./version.txt
    shtool version -n "{{EXE}}" -d long -l txt ./version.txt >{{XDIR}}/version_info.txt

inc-major:
    #!/bin/bash
    cd {{XDIR}}
    shtool version -n "{{EXE}}" -i r -l txt ./version.txt
    shtool version -n "{{EXE}}" -d long -l txt ./version.txt >{{XDIR}}/version_info.txt

inc-level:
    #!/bin/bash
    cd {{XDIR}}
    shtool version -n "{{EXE}}" -i l -l txt ./version.txt
    shtool version -n "{{EXE}}" -d long -l txt ./version.txt >{{XDIR}}/version_info.txt

set-version _VERSION:
    #!/bin/bash
    cd {{XDIR}}
    shtool version -n "{{EXE}}" -s "{{_VERSION}}" -l txt ./version.txt
    shtool version -n "{{EXE}}" -d long -l txt ./version.txt >{{XDIR}}/version_info.txt

make-release: set-drel build
    #!/bin/bash
    VERSION=$(grep -oP ".*, Version \K[^ ]+" ./version.txt)
    MESSAGE="automated release version $(shtool version -l text -d long ./version.txt)"
    shtool version -n "{{EXE}}" -d long -l txt ./version.txt >{{XDIR}}/version_info.txt
    git commit -m "upd $VERSION"
    git push
    gh release create v$VERSION --notes "$MESSAGE" out/{{EXE}}-*

gen-test-keys:
    #!/bin/sh -x
    certtool --bits 1024 -p > test/rsa.1024.pem
    openssl pkey -pubout < test/rsa.1024.pem  > test/rsa.1024.pub
    C=$(openssl ecparam -list_curves|fgrep :|cut -f1 -d:)
    for x in $C; do
        openssl ecparam -out test/ec_key.$x.pem -name $x -genkey
        openssl ec -in test/ec_key.$x.pem -out test/ec_key.$x.pub -pubout
    done


build: fetch-assets
    #!/bin/sh
    export GOROOT=${HOME}/bin/go
    export PATH=$GOROOT/bin:$PATH
    rm -rf {{XDIR}}/out
    mkdir {{XDIR}}/out
    #$ grep -oP ".*, Version \K.+" ./version.txt
    VERSION=$(grep -oP ".*, Version \K[^ ]+" ./version.txt)
    shtool version -n "{{EXE}}" -d long -l txt ./version.txt >{{XDIR}}/version_info.txt
    go build -o {{XEXE}} cmd/*.go
    cp -v {{XEXE}} {{XDIR}}/out/{{EXE}}-v$VERSION-{{XARCH}}

