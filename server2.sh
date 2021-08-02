#/usr/bin/

if [ -f "${1}/reachable.dummy" ]; then
    echo "success"
else
    echo "failure"
fi

