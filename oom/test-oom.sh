#!/bin/bash
#
# This is a test to ensure the parca-agent can detect and handle "self" OOMs,
# ie the parent process watches the child for OOM events and reports them.
# Currently not a full circle test and has to be verified manually by
# inspecting parca for the oom profile.

set -e

# Configuration
MEMORY_LIMIT="1500M"
CGROUP_NAME="parca-oom-test"
SIGNAL_TO_SEND="USR2"
SLEEP_TIME=15
PARCA_PORT="${PARCA_PORT:-7070}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date '+%H:%M:%S')] WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date '+%H:%M:%S')] ERROR:${NC} $1"
}

# Function to cleanup cgroup
cleanup() {
    log "Cleaning up..."
    if [ -n "$PARCA_PID" ]; then
        log "Killing parca-agent (PID: $PARCA_PID)"
        kill -TERM "$PARCA_PID" 2>/dev/null || true
        wait "$PARCA_PID" 2>/dev/null || true
    fi

    # Remove from cgroup
    if [ -f "/sys/fs/cgroup/${CGROUP_NAME}/cgroup.procs" ]; then
        echo $$ > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true
    fi

    # Stop bpftrace if running
    if [ -n "$BPFTRACE_PID" ]; then
        log "Stopping bpftrace (PID: $BPFTRACE_PID)"
        kill "$BPFTRACE_PID" 2>/dev/null || true
        wait "$BPFTRACE_PID" 2>/dev/null || true
    fi

    # Remove cgroup
    if [ -d "/sys/fs/cgroup/${CGROUP_NAME}" ]; then
        log "Removing cgroup: $CGROUP_NAME"
        rmdir "/sys/fs/cgroup/${CGROUP_NAME}" 2>/dev/null || true
    fi
}

# Set up cleanup on exit
trap cleanup EXIT

# Variable to store bpftrace PID
BPFTRACE_PID=""

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then
    error "This script needs to be run with sudo to manage cgroups"
    exit 1
fi

# Check if cgroup v2 is available
if [ ! -f "/sys/fs/cgroup/cgroup.controllers" ]; then
    error "cgroup v2 is required but not found"
    exit 1
fi

# Function to get detailed memory breakdown for a process
get_process_memory_detail() {
    local pid=$1
    local proc_name=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")

    if [[ ! -d "/proc/$pid" ]]; then
        echo "Process $pid not found"
        return
    fi

    log "=== Memory Analysis for PID $pid ($proc_name) ==="

    # Basic memory stats from /proc/pid/status
    if [[ -f "/proc/$pid/status" ]]; then
        log "Process Status Memory:"
        grep -E "^(VmSize|VmRSS|VmHWM|VmData|VmStk|VmExe|VmLib|VmPTE|VmSwap)" "/proc/$pid/status" | while read -r line; do
            log "  $line"
        done
    fi

    # Memory maps breakdown
    if [[ -f "/proc/$pid/smaps" ]]; then
        log "Memory Maps Summary:"
        local heap_size=$(grep -A 20 "\[heap\]" "/proc/$pid/smaps" | grep "^Size:" | awk '{print $2}' | head -1)
        local stack_size=$(grep -A 20 "\[stack\]" "/proc/$pid/smaps" | grep "^Size:" | awk '{print $2}' | head -1)
        local anon_total=$(grep "^Size:" "/proc/$pid/smaps" | awk '{total+=$2} END {print total}')
        local rss_total=$(grep "^Rss:" "/proc/$pid/smaps" | awk '{total+=$2} END {print total}')

        log "  Heap: ${heap_size:-0} kB"
        log "  Stack: ${stack_size:-0} kB"
        log "  Total Size: ${anon_total:-0} kB"
        log "  Total RSS: ${rss_total:-0} kB"

        # Show top memory consumers
        log "  Top Memory Regions:"
        awk '/^[0-9a-f]/ {addr=$1} /^Size:/ {size=$2} /^Rss:/ {rss=$2} /^[0-9a-f].*\[/ {name=$NF} END {if(rss>1024) print "    " addr " " size "kB/" rss "kB " name}' "/proc/$pid/smaps" | sort -k3 -nr | head -10
    fi

    # Show file descriptors count
    local fd_count=$(ls -1 "/proc/$pid/fd/" 2>/dev/null | wc -l)
    log "  File Descriptors: $fd_count"

    # Show threads
    local thread_count=$(ls -1 "/proc/$pid/task/" 2>/dev/null | wc -l)
    log "  Threads: $thread_count"

    log ""
}

# Function to compare parent and child memory usage
compare_parent_child_memory() {
    local parent_pid=$1

    # Get all child processes
    local children=$(pgrep -P "$parent_pid" 2>/dev/null)

    get_process_memory_detail "$parent_pid"

    if [[ -n "$children" ]]; then
        for child_pid in $children; do
            get_process_memory_detail "$child_pid"
        done
    else
        log "No child processes found for PID $parent_pid"
    fi
}

# Build parca-agent with oomtest tag
log "Building parca-agent with oomtest tag..."
go build -tags oomtest -o parca-agent-oomtest .
if [ $? -ne 0 ]; then
    error "Failed to build parca-agent with oomtest tag"
    exit 1
fi

PARCA_BINARY="./parca-agent-oomtest"

log "Setting up memory-limited cgroup for OOM testing"

# Create cgroup
CGROUP_PATH="/sys/fs/cgroup/${CGROUP_NAME}"
log "Creating cgroup: $CGROUP_NAME with memory limit: $MEMORY_LIMIT"
mkdir -p "$CGROUP_PATH"

# Enable memory controller
echo "+memory" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true

# Set memory limit
echo "$MEMORY_LIMIT" > "${CGROUP_PATH}/memory.max"
echo "$MEMORY_LIMIT" > "${CGROUP_PATH}/memory.high"

# Start bpftrace for OOM monitoring
log "Starting bpftrace OOM monitoring..."
if command -v bpftrace >/dev/null 2>&1; then
    bpftrace ./oom_trace.bt &
    BPFTRACE_PID=$!
    log "Started bpftrace with PID: $BPFTRACE_PID"
    # Give bpftrace a moment to start up
    sleep 2
else
    warn "bpftrace not found - OOM tracing will be disabled"
fi

if ! lsof -i :"$PARCA_PORT" >/dev/null 2>&1; then
    docker run -d --name parca -p "$PARCA_PORT:$PARCA_PORT" ghcr.io/parca-dev/parca:v0.24.0
fi

log "Starting parca-agent with OOM testing enabled..."

# Start parca-agent in the background
"$PARCA_BINARY" \
    "--remote-store-address=localhost:$PARCA_PORT" \
    --remote-store-insecure \
    --enable-oom-prof=true &

PARCA_PID=$!

# Add the process to the cgroup
echo "$PARCA_PID" > "${CGROUP_PATH}/cgroup.procs"

log "Started parca-agent with PID: $PARCA_PID"
log "Memory limit: $MEMORY_LIMIT"
log "Cgroup: $CGROUP_NAME"

# Wait for parca-agent to start up
log "Waiting ${SLEEP_TIME}s for parca-agent to start up..."
sleep "$SLEEP_TIME"

# Check if process is still running
if ! kill -0 "$PARCA_PID" 2>/dev/null; then
    error "parca-agent process died during startup"
    exit 1
fi

# Show current memory usage
log "Current memory usage:"
if [ -f "${CGROUP_PATH}/memory.current" ]; then
    mem=$(cat "${CGROUP_PATH}/memory.current")
    mem_mb=$((mem / 1024 / 1024))
    log "  Current: ${mem_mb}MB"
fi

log "=== PRE-OOM Memory Analysis ==="
compare_parent_child_memory "$PARCA_PID"

# Get the child process PID
CHILD_PID=$(pgrep -P "$PARCA_PID" 2>/dev/null)
if [[ -n "$CHILD_PID" ]]; then
    log "Sending $SIGNAL_TO_SEND signal to child process (PID: $CHILD_PID) to trigger OOM..."
    kill -"$SIGNAL_TO_SEND" "$CHILD_PID"
else
    log "No child process found, sending signal to parent process..."
    kill -"$SIGNAL_TO_SEND" "$PARCA_PID"
fi

log "Monitoring for OOM events..."

# Function to get BPF memory usage for a process and its children
get_bpf_memory() {
    local main_pid=$1
    local total_memlock=0
    local map_count=0
    local prog_count=0
    local detailed_info=""

    # Get all child PIDs
    local all_pids=$(pgrep -P "$main_pid" 2>/dev/null | tr '\n' ' ')
    all_pids="$main_pid $all_pids"

    log "Checking BPF usage for PIDs: $all_pids"

    # Get programs loaded by root (uid 0) - parca-agent runs as root
    while IFS= read -r prog_json; do
        if [[ -n "$prog_json" ]]; then
            local prog_id=$(echo "$prog_json" | jq -r '.id')
            local prog_name=$(echo "$prog_json" | jq -r '.name // "unnamed"')
            local prog_memlock=$(echo "$prog_json" | jq -r '.bytes_memlock')
            local prog_uid=$(echo "$prog_json" | jq -r '.uid')

            # Only count programs loaded by root (parca-agent)
            if [[ "$prog_uid" == "0" ]]; then
                prog_count=$((prog_count + 1))
                total_memlock=$((total_memlock + prog_memlock))
                local prog_mb=$((prog_memlock / 1024 / 1024))
                if [[ $prog_mb -gt 0 ]]; then
                    detailed_info="${detailed_info}  PROG $prog_id: $prog_name (${prog_mb}MB)\n"
                fi
            fi
        fi
    done < <(bpftool prog show -j 2>/dev/null | jq -c '.[]?' 2>/dev/null || echo "")

    # Get maps and their memory usage
    while IFS= read -r map_json; do
        if [[ -n "$map_json" ]]; then
            local map_id=$(echo "$map_json" | jq -r '.id')
            local map_name=$(echo "$map_json" | jq -r '.name // "unnamed"')
            local map_memlock=$(echo "$map_json" | jq -r '.bytes_memlock')
            local map_type=$(echo "$map_json" | jq -r '.type')

            # Only count maps > 1MB to focus on large consumers
            local map_mb=$((map_memlock / 1024 / 1024))
            if [[ $map_mb -gt 1 ]]; then
                map_count=$((map_count + 1))
                total_memlock=$((total_memlock + map_memlock))
                detailed_info="${detailed_info}  MAP $map_id: $map_name [$map_type] (${map_mb}MB)\n"
            fi
        fi
    done < <(bpftool map show -j 2>/dev/null | jq -c '.[]?' 2>/dev/null || echo "")

    local total_mb=$((total_memlock / 1024 / 1024))

    # Show detailed info if there's significant memory usage
    if [[ $total_mb -gt 10 ]]; then
        log "BPF Memory Details:"
        echo -e "$detailed_info" | head -20
    fi

    echo "${total_mb}MB (${map_count} large maps, ${prog_count} progs)"
}

# Monitor the process and memory usage
for i in {1..60}; do
    if ! kill -0 "$PARCA_PID" 2>/dev/null; then
        log "Process has terminated (likely OOM killed)"
        break
    fi

    # Show memory usage every second
    mem=$(cat "${CGROUP_PATH}/memory.current" 2>/dev/null || echo "0")
    mem_mb=$((mem / 1024 / 1024))
    mem_limit_mb=$(echo "$MEMORY_LIMIT" | sed 's/M$//')

    # Get BPF memory usage
    bpf_memory=$(get_bpf_memory "$PARCA_PID")

    log "Memory usage: ${mem_mb}MB / ${mem_limit_mb}MB | BPF: ${bpf_memory}"

    # Show detailed memory analysis every 10 seconds
    if [[ $((i % 10)) -eq 0 ]]; then
        log "=== Detailed Memory Analysis (iteration $i) ==="
        compare_parent_child_memory "$PARCA_PID"
    fi

    # Check for OOM events and show all memory.events contents
    if [ -f "${CGROUP_PATH}/memory.events" ]; then
        log "Current memory.events:"
        cat "${CGROUP_PATH}/memory.events" | while read line; do
            log "  $line"
        done

        oom_kill=$(grep "oom_kill" "${CGROUP_PATH}/memory.events" | awk '{print $2}')
        if [ "$oom_kill" -gt "0" ]; then
            log "OOM kill detected! (count: $oom_kill)"
        fi
    fi

    sleep 1
done

# Final check
if kill -0 "$PARCA_PID" 2>/dev/null; then
    warn "Process is still running after 60 seconds"
else
    log "Process has terminated"

    # Check exit status
    wait "$PARCA_PID"
    EXIT_CODE=$?
    if [ $EXIT_CODE -eq 137 ]; then
        log "Process was killed with SIGKILL (likely OOM)"
    else
        log "Process exited with code: $EXIT_CODE"
    fi

    # Check for OOM events in cgroup
    if [ -f "${CGROUP_PATH}/memory.events" ]; then
        log "Memory events:"
        cat "${CGROUP_PATH}/memory.events" | while read line; do
            log "  $line"
        done
    fi

    # Check dmesg for OOM messages
    log "Checking dmesg for OOM messages..."
    dmesg | tail -20 | grep -i "killed process\|out of memory\|oom-kill" || log "No OOM messages found in recent dmesg"
fi

log "OOM test completed"