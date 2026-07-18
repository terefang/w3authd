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

set-drel: inc-level
    #!/bin/bash
    V=$(date '+%Y.%m.')
    V=$V$(cd {{XDIR}} && shtool version -l short {{XDIR}}/version.txt|cut -f 3 -d.)
    cd {{XDIR}} && just -f justfile set-version "$V"

inc-version:
    #!/bin/bash
    cd {{XDIR}} && shtool version -i v -l txt {{XDIR}}/version.txt

inc-major:
    #!/bin/bash
    cd {{XDIR}} && shtool version -i r -l txt {{XDIR}}/version.txt

inc-level:
    #!/bin/bash
    cd {{XDIR}} && shtool version -i l -l txt {{XDIR}}/version.txt

set-version _VERSION:
    #!/bin/bash
    cd {{XDIR}} && shtool version -s "{{_VERSION}}" -l txt {{XDIR}}/version.txt

make-release:
    #!/bin/bash
    VERSION=$(shtool version -l txt {{XDIR}}/version.txt)
    MESSAGE="automated release version $(shtool version -l text -d long {{XDIR}}/version.txt)"
    gh release create v$VERSION --notes "$MESSAGE"

build: fetch-assets
    #!/bin/sh
    export GOROOT=${HOME}/bin/go
    export PATH=$GOROOT/bin:$PATH
    go build -o {{XEXE}} cmd/main.go