#!/usr/bin/env python3
"""
Step 5 — PE Export & TLS Callback Analysis
Read-only. Lists all exports, TLS callbacks, and the entry point.

Usage: python 05_exports.py <sample_path>
Output: JSON to stdout
"""

import json
import struct
import sys


def analyze_exports(path: str) -> dict:
    try:
        import pefile
    except ImportError:
        return {"error": "pefile not installed. Run: pip install pefile"}

    try:
        pe = pefile.PE(path)
    except Exception as e:
        return {"error": f"Failed to parse PE: {e}"}

    is_64bit   = pe.PE_TYPE == 0x20b
    image_base = pe.OPTIONAL_HEADER.ImageBase

    # --- Entry Point ---
    ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    entry_point = {
        "rva":     f"0x{ep_rva:08X}",
        "va":      f"0x{image_base + ep_rva:016X}" if is_64bit else f"0x{image_base + ep_rva:08X}",
    }

    # --- Exports ---
    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = sym.name.decode(errors="replace") if sym.name else None
            exports.append({
                "ordinal": sym.ordinal,
                "rva":     f"0x{sym.address:08X}",
                "name":    name,
            })

    # --- TLS Callbacks ---
    tls_callbacks = []
    if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
        tls      = pe.DIRECTORY_ENTRY_TLS.struct
        cb_va    = tls.AddressOfCallBacks
        ptr_size = 8 if is_64bit else 4
        fmt      = "<Q" if is_64bit else "<I"

        if cb_va:
            cb_rva = cb_va - image_base
            try:
                offset = pe.get_offset_from_rva(cb_rva)
                while True:
                    raw = pe.__data__[offset: offset + ptr_size]
                    if len(raw) < ptr_size:
                        break
                    cb_abs = struct.unpack(fmt, raw)[0]
                    if cb_abs == 0:
                        break
                    cb_rva_val = cb_abs - image_base
                    tls_callbacks.append({
                        "rva": f"0x{cb_rva_val:08X}",
                        "va":  f"0x{cb_abs:016X}" if is_64bit else f"0x{cb_abs:08X}",
                    })
                    offset += ptr_size
            except Exception as e:
                tls_callbacks.append({"error": f"Failed to walk TLS callback array: {e}"})

    pe.close()

    return {
        "architecture":    "PE32+" if is_64bit else "PE32",
        "image_base":      f"0x{image_base:016X}" if is_64bit else f"0x{image_base:08X}",
        "entry_point":     entry_point,
        "export_count":    len(exports),
        "exports":         exports,
        "tls_callback_count": len(tls_callbacks),
        "tls_callbacks":   tls_callbacks,
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python 05_exports.py <sample_path>", file=sys.stderr)
        sys.exit(1)

    result = analyze_exports(sys.argv[1])
    print(json.dumps(result, indent=2))
