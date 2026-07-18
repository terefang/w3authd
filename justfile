#!/usr/bin/env just --justfile

XDIR := justfile_directory()
EXE := "w3authd"
XEXE := XDIR+'/'+EXE

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

build: fetch-assets
    #!/bin/sh
    export GOROOT=${HOME}/bin/go
    export PATH=$GOROOT/bin:$PATH
    go build -o {{XEXE}} cmd/main.go