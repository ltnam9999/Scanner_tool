#!/bin/bash
# ============================================================
# RUN DOMAIN SCANNER — WSL2
# Cách dùng: bash run_scan.sh [số_workers] [limit]
# Ví dụ:
#   bash run_scan.sh           # Chạy full 2M, 300 workers
#   bash run_scan.sh 200       # 200 workers
#   bash run_scan.sh 300 100   # 300 workers, chỉ 100 domains (test)
# ============================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INPUT_CSV="${SCRIPT_DIR}/labeled_domains.csv"
OUTPUT_DIR="${SCRIPT_DIR}/scan_output"
FINAL_JSON="${SCRIPT_DIR}/scanned_all.json"
SCANNER="${SCRIPT_DIR}/scanner_async.py"

WORKERS=${1:-300}
LIMIT=${2:-0}

echo "=============================================="
echo "  DOMAIN SCANNER — WSL2"
echo "=============================================="
echo "  Input:   ${INPUT_CSV}"
echo "  Output:  ${OUTPUT_DIR}/"
echo "  Workers: ${WORKERS}"
echo "  Limit:   ${LIMIT} (0=all)"
echo "=============================================="

# Check input exists
if [ ! -f "$INPUT_CSV" ]; then
    echo "[ERROR] Input CSV not found: $INPUT_CSV"
    echo "  Copy labeled_domains.csv to: $SCRIPT_DIR/"
    exit 1
fi

# Count domains
DOMAIN_COUNT=$(wc -l < "$INPUT_CSV")
echo "  Domains in CSV: ${DOMAIN_COUNT}"

# Check dependencies
echo ""
echo "[*] Checking dependencies..."
python3 -c "import dns.resolver, aiodns, aiohttp, OpenSSL; print('  ✅ All OK')" 2>/dev/null || {
    echo "  [!] Missing dependencies. Running setup..."
    bash "${SCRIPT_DIR}/setup_wsl2.sh"
}

# Tăng FD limit cho session hiện tại
ulimit -n 65535 2>/dev/null || ulimit -n 32768 2>/dev/null || ulimit -n 10240
echo "  FD limit: $(ulimit -n)"

# Create output dir
mkdir -p "$OUTPUT_DIR"

# Check resume
if [ -f "${OUTPUT_DIR}/results.jsonl" ]; then
    DONE_COUNT=$(wc -l < "${OUTPUT_DIR}/done_domains.txt" 2>/dev/null || echo "0")
    echo ""
    echo "  [RESUME] Found existing checkpoint: ${DONE_COUNT} domains done"
    echo "  Will continue from where it stopped."
fi

# Run scanner
echo ""
echo ">>> Starting scanner ($(date))..."
echo ">>> Ctrl+C to pause (progress is auto-saved)"
echo ""

LIMIT_ARG=""
if [ "$LIMIT" -gt 0 ] 2>/dev/null; then
    LIMIT_ARG="--limit $LIMIT"
fi

python3 "$SCANNER" \
    --input "$INPUT_CSV" \
    --output "$OUTPUT_DIR" \
    --workers "$WORKERS" \
    $LIMIT_ARG

echo ""
echo ">>> Scanner finished ($(date))"

# Auto-merge to final JSON
if [ -f "${OUTPUT_DIR}/results.jsonl" ]; then
    echo ""
    echo "=============================================="
    echo "  MERGING TO FINAL JSON..."
    echo "=============================================="

    python3 "${SCRIPT_DIR}/merge_results.py" \
        --input "$OUTPUT_DIR" \
        --output "$FINAL_JSON"

    echo ""
    echo "=============================================="
    echo "  ✅ DONE!"
    echo "  Final output: ${FINAL_JSON}"
    SIZE=$(du -sh "$FINAL_JSON" 2>/dev/null | cut -f1)
    echo "  Size: ${SIZE}"
    echo "=============================================="
fi
