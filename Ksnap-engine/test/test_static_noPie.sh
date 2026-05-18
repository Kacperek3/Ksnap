#!/bin/bash

GREEN='\033[0-9;32m'
RED='\033[0-9;31m'
NC='\033[0m'

>test/logs.txt

echo "Starting tests"
cd test_programs

./counter_static_noPie >>../test/logs.txt &
PID=$!
sleep 5

echo "Making process dump $PID..."
../build/Ksnap -m Dump -p $PID

LAST_VAL=$(tail -n 1 ../test/logs.txt)

kill -9 $PID 2>/dev/null
wait $PID 2>/dev/null

echo "Dump made on value: $LAST_VAL"
echo "Restoring process..."

../build/Ksnap -m Restore &
NEW_PID=$!
sleep 2

kill -9 $NEW_PID 2>/dev/null
wait $NEW_PID 2>/dev/null

NEXT_VAL=$(grep -A 1 "^${LAST_VAL}$" ../test/logs.txt | tail -n 1)
EXPECTED=$((LAST_VAL))

if [ "$NEXT_VAL" -eq "$EXPECTED" ]; then
    echo -e "${GREEN}TEST PASSED: ($LAST_VAL -> $NEXT_VAL)!${NC}"
else
    echo -e "${RED}TEST FAILED: expected $EXPECTED, but is '$NEXT_VAL'${NC}"
    exit 1
fi
