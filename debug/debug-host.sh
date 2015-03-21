cd linux-2.6.32.65/
socat /tmp/dbg_pipe TCP4-LISTEN:9001 &
gdb vmlinux -x ../gdb_script
