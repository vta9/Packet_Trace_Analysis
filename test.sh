#!/bin/bash

# Directories and program
SAMPLE_DIR="/325-samples/p3"
PROG="./proj3"

# Temporary output files
TMP_OUT="proj3_test_output.txt"
TMP_SORTED_OUT="proj3_test_output_sorted.txt"
TMP_EXPECT_SORTED="expected_output_sorted.txt"

# Colors
GREEN=$(tput setaf 2)
RED=$(tput setaf 1)
YELLOW=$(tput setaf 3)
RESET=$(tput sgr0)

# Counters
total=0
passed=0
failed=0

echo "Running proj3 tests..."
echo "-----------------------------------------"

run_test() {
    local mode=$1
    local trace=$2
    local expected=$3
    local sort_needed=$4

    total=$((total + 1))
    local basename=$(basename "$trace")

    if [ ! -f "$expected" ]; then
        echo "${YELLOW} Skipping${RESET} $basename$mode (no expected output found)"
        return
    fi

    # Run proj3
    $PROG "$mode" -f "$trace" > "$TMP_OUT" 2>/dev/null

    # Sort if needed
    if [ "$sort_needed" = true ]; then
        sort "$TMP_OUT" > "$TMP_SORTED_OUT"
        sort "$expected" > "$TMP_EXPECT_SORTED"
        diff -q "$TMP_SORTED_OUT" "$TMP_EXPECT_SORTED" > /dev/null
    else
        diff -q "$TMP_OUT" "$expected" > /dev/null
    fi

    if [ $? -eq 0 ]; then
        echo "${GREEN}PASS${RESET}  $basename $mode"
        passed=$((passed + 1))
    else
        echo "${RED}FAIL${RESET}  $basename $mode"
        echo "  → Diff (first 5 lines):"
        if [ "$sort_needed" = true ]; then
            diff "$TMP_SORTED_OUT" "$TMP_EXPECT_SORTED" | head -n 5
        else
            diff "$TMP_OUT" "$expected" | head -n 5
        fi
        failed=$((failed + 1))
    fi
}

# --- Test sample traces in /325-samples/p3 ---
for mode in -r -n -p; do
    echo "=== Testing mode $mode in $SAMPLE_DIR ==="

    for trace in "$SAMPLE_DIR"/*.trace; do
        basename=$(basename "$trace" .trace)
        expected="$SAMPLE_DIR/${basename}${mode}.out"
        sort_needed=false
        if [[ "$mode" == "-r" || "$mode" == "-n" ]]; then
            sort_needed=true
        fi
        run_test "$mode" "$trace" "$expected" "$sort_needed"
    done
    echo ""
done

# --- Test local stress.trace ---
echo "=== Testing stress.trace ==="
if [ -f "stress.trace" ]; then
    if [ -f "stress-n.out.txt" ]; then
        run_test "-n" "stress.trace" "stress-n.out.txt" true
    fi
    if [ -f "stress-r.out.txt" ]; then
        run_test "-r" "stress.trace" "stress-r.out.txt" true
    fi
else
    echo "${YELLOW}  Skipping stress.trace (file not found)${RESET}"
fi

# --- Summary ---
echo "-----------------------------------------"
echo "Tests run: $total"
echo "${GREEN}Passed:${RESET} $passed"
echo "${RED}Failed:${RESET} $failed"
echo "-----------------------------------------"

# Cleanup temp files
rm -f "$TMP_OUT" "$TMP_SORTED_OUT" "$TMP_EXPECT_SORTED"
