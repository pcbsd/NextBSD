#!/bin/sh
#
# PROVIDE: setup_mach
# REQUIRE: tmp
# BEFORE: local
#
LOADER_CONF=/tmp/bsdinstall_boot/loader.conf.mach
mkdir -p "${LOADER_CONF%/*}" || exit
cat <<-'EOF' > "$LOADER_CONF"
        init_path="/sbin/launchd"
        mach_load="YES"
EOF
