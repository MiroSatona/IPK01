#!/bin/bash

FILE="../.././ipk-l4-scan"

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' 

test_program_invalid() {
    local test_name="$1"
    shift

    echo "$test_name"

    output=$( "$FILE" "$@" 2>&1 )
    rc=$?

    if [[ $rc -eq 1 && "$output" == *"Error: Invalid input was pasted!"* ]]; then
        echo -e "${GREEN}PASSED${NC}"
    else
        echo -e "${RED}FAILED${NC}"
        echo "Return code: $rc"
        echo "Stderr: $output"
    fi

    echo "-------------------------"
}

# Testing invalid inputs
test_program_invalid "TEST01: ./ipk-l4-scan --interface eth0" --interface eth0
test_program_invalid "TEST02: ./ipk-l4-scan example.com" example.com
test_program_invalid "TEST03: ./ipk-l4-scan --ipk 10" --ipk 10
test_program_invalid "TEST04: ./ipk-l4-scan --pu 53" --pu 53
test_program_invalid "TEST05: ./ipk-l4-scan --pu 53 -u 45" --pu 53 -u 45
test_program_invalid "TEST06: ./ipk-l4-scan --interface todo 127.0.0.1 --wait 10 --pt 80,443 --pu 53,123" --interface todo 127.0.0.1 --wait 10 --pt 80,443 --pu 53,123
test_program_invalid "TEST07: ./ipk-l4-scan --interface lo www.google.com --wait 10 --pt 80,443,smile --pu 53,123" --interface lo www.google.com --wait 10 --pt 80,443,smile --pu 53,123
test_program_invalid "TEST08: ./ipk-l4-scan --interface lo www.google.com --wait 10 --pt 10-3 --pu 53,123" --interface lo www.google.com --wait 10 --pt 10-3 --pu 53,123
test_program_invalid "TEST09: ./ipk-l4-scan --interface lo www.google.com --wait 10 --pt 22,22,22 --pu 53,123" --interface lo www.google.com --wait 10 --pt 22,22,22 --pu 53,123
test_program_invalid "TEST10: ./ipk-l4-scan --interface lo www.google.com --wait xxxx --pt 443 --pu 53,123" --interface lo www.google.com --wait xxxx --pt 443 --pu 53,123
test_program_invalid "TEST11: ./ipk-l4-scan --interface lo www.example.brno --wait 10 --pt 443 --pu 53,123" --interface lo www.example.brno --wait 10 --pt 443 --pu 53,123
test_program_invalid "TEST12: ./ipk-l4-scan --interface lo 2001:0db8:85a3:0000:0000:8a2e:0370:7334:1111 --wait 10 --pt 443 --pu 53,123" --interface lo 2001:0db8:85a3:0000:0000:8a2e:0370:7334:1111 --wait 10 --pt 443 --pu 53,123
test_program_invalid "TEST13: ./ipk-l4-scan --interface lo 127.0.0.1 --wait 10 --pt 22.2 --pu 53,123" --interface lo 127.0.0.1 --wait 10 --pt 22.2 --pu 53,123
test_program_invalid "TEST14: ./ipk-l4-scan --interface lo 127.0.0.1.1 --wait 10 --pt 22 --pu 53,123" --interface lo 127.0.0.1.1 --wait 10 --pt 22 --pu 53,123
test_program_invalid "TEST15: ./ipk-l4-scan --interface lo www.google.com" --interface lo www.google.com -t 100000000000
