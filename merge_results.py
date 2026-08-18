#!/usr/bin/env python3
"""
Merge JSONL results thành JSON array cuối cùng.
Dùng streaming để không tốn RAM.

Cách dùng:
    python3 merge_results.py --input scan_output/ --output final_scanned.json
    python3 merge_results.py --input scan_output/ --output final_scanned.json --pretty
"""

import argparse
import json
import os
import sys


def merge_jsonl_to_json(input_dir, output_file, pretty=False):
    """Merge JSONL file(s) trong input_dir thành 1 JSON array"""
    jsonl_path = os.path.join(input_dir, 'results.jsonl')

    if not os.path.exists(jsonl_path):
        print(f"[ERROR] Không tìm thấy {jsonl_path}")
        sys.exit(1)

    file_size = os.path.getsize(jsonl_path) / (1024 * 1024)
    print(f"[*] Input: {jsonl_path} ({file_size:.1f} MB)")
    print(f"[*] Output: {output_file}")

    # Count lines first
    total_lines = 0
    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for _ in f:
            total_lines += 1
    print(f"[*] Records: {total_lines:,}")

    # Stream write JSON array
    written = 0
    errors = 0

    indent = 2 if pretty else None
    sep_record = ',\n' if pretty else ','

    with open(output_file, 'w', encoding='utf-8') as out:
        out.write('[\n' if pretty else '[')

        with open(jsonl_path, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue

                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    errors += 1
                    continue

                if written > 0:
                    out.write(sep_record)

                if pretty:
                    out.write('  ' + json.dumps(record, indent=2, ensure_ascii=False, default=str).replace('\n', '\n  '))
                else:
                    out.write(json.dumps(record, ensure_ascii=False, default=str))

                written += 1

                if written % 100000 == 0:
                    print(f"  [{written:>10,}/{total_lines:,}] writing...")

        out.write('\n]' if pretty else ']')

    out_size = os.path.getsize(output_file) / (1024 * 1024)

    print(f"\n{'=' * 50}")
    print(f"  MERGE COMPLETE")
    print(f"{'=' * 50}")
    print(f"  Records written: {written:,}")
    print(f"  Errors skipped:  {errors:,}")
    print(f"  Output size:     {out_size:.1f} MB")
    print(f"  Output file:     {output_file}")
    print(f"{'=' * 50}")

    # Quick stats
    print(f"\n[*] Sampling data quality (first 10000 records)...")
    sample_count = 0
    has_dns = has_tls = has_rdap = has_ip = 0
    cat_counts = {}

    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for line in f:
            if sample_count >= 10000:
                break
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                sample_count += 1
                if r.get('dns'):
                    has_dns += 1
                if r.get('tls'):
                    has_tls += 1
                if r.get('rdap'):
                    has_rdap += 1
                if r.get('ip_data'):
                    has_ip += 1
                cat = str(r.get('category', '?'))
                cat_counts[cat] = cat_counts.get(cat, 0) + 1
            except Exception:
                pass

    if sample_count > 0:
        print(f"  Sample size: {sample_count:,}")
        print(f"  Has DNS:  {has_dns:,} ({has_dns/sample_count*100:.1f}%)")
        print(f"  Has TLS:  {has_tls:,} ({has_tls/sample_count*100:.1f}%)")
        print(f"  Has RDAP: {has_rdap:,} ({has_rdap/sample_count*100:.1f}%)")
        print(f"  Has IP:   {has_ip:,} ({has_ip/sample_count*100:.1f}%)")
        print(f"  Categories: {cat_counts}")


def main():
    parser = argparse.ArgumentParser(description='Merge JSONL → JSON array')
    parser.add_argument('--input', '-i', required=True,
                        help='Input directory chứa results.jsonl')
    parser.add_argument('--output', '-o', required=True,
                        help='Output file JSON')
    parser.add_argument('--pretty', '-p', action='store_true',
                        help='Pretty-print JSON (file sẽ lớn hơn)')
    args = parser.parse_args()

    merge_jsonl_to_json(args.input, args.output, args.pretty)


if __name__ == '__main__':
    main()
