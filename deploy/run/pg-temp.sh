#!/usr/bin/env bash
# A throw-away PostgreSQL server for the UDR's tests and for development (no root, no system service).
#   pg-temp.sh start <dir>   initialise <dir> if empty, start a server on a unix socket in <dir>, create the database
#                            and print the libpq connection string on stdout
#   pg-temp.sh stop <dir>    stop it (fast shutdown) and leave the data in place
#   pg-temp.sh drop <dir>    stop it and delete <dir>
# The server binaries come from G5C_PG_BIN, from an unpacked package tree in G5C_PG_ROOT (default ~/pg-local/root: the
# postgresql-NN .deb files unpacked with dpkg-deb -x), or from the system. Exit status 77 when none is found.
set -euo pipefail
cmd="${1:-}"; dir="${2:-}"
[ -n "$cmd" ] && [ -n "$dir" ] || { echo "usage: pg-temp.sh start|stop|drop <dir>" >&2; exit 2; }
root="${G5C_PG_ROOT:-$HOME/pg-local/root}"
bin="${G5C_PG_BIN:-}"
if [ -z "$bin" ]; then
  for d in "$root"/usr/lib/postgresql/*/bin /usr/lib/postgresql/*/bin; do [ -x "$d/initdb" ] && bin="$d"; done
fi
[ -n "$bin" ] && [ -x "$bin/initdb" ] || { echo "SKIP: no PostgreSQL server binaries (set G5C_PG_BIN or G5C_PG_ROOT)" >&2; exit 77; }
if [ -d "$root/usr/lib/x86_64-linux-gnu" ]; then
  export LD_LIBRARY_PATH="$root/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi
sock="$dir/sock"
port="${G5C_PG_PORT:-54329}"
case "$cmd" in
  start)
    mkdir -p "$dir" "$sock"
    if [ ! -f "$dir/data/PG_VERSION" ]; then
      "$bin/initdb" -D "$dir/data" --auth=trust --encoding=UTF8 --locale=C.UTF-8 -U g5c >"$dir/initdb.log" 2>&1 \
        || { cat "$dir/initdb.log" >&2; exit 1; }
    fi
    if ! "$bin/pg_ctl" -D "$dir/data" status >/dev/null 2>&1; then
      "$bin/pg_ctl" -D "$dir/data" -l "$dir/server.log" -w -t 60 \
        -o "-k $sock -p $port -c listen_addresses= -c fsync=off -c synchronous_commit=off -c full_page_writes=off" start >/dev/null \
        || { cat "$dir/server.log" >&2; exit 1; }
    fi
    "$bin/psql" -h "$sock" -p "$port" -U g5c -d postgres -tAc "select 1 from pg_database where datname='g5c_udr'" | grep -q 1 \
      || "$bin/psql" -h "$sock" -p "$port" -U g5c -d postgres -qc "create database g5c_udr" >/dev/null
    echo "host=$sock port=$port user=g5c dbname=g5c_udr"
    ;;
  stop)
    "$bin/pg_ctl" -D "$dir/data" -m fast -w stop >/dev/null 2>&1 || true
    ;;
  drop)
    "$bin/pg_ctl" -D "$dir/data" -m immediate -w stop >/dev/null 2>&1 || true
    rm -rf "$dir"
    ;;
  *) echo "unknown command $cmd" >&2; exit 2 ;;
esac
