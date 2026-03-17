"""
app.py — Flask web application for Check Point VSX → Panorama migration.

Run with:
    py app.py
    python app.py
    flask run

Opens at http://localhost:5000
"""

import os
import base64
import json
import logging
import traceback
from datetime import datetime

from flask import (
    Flask, render_template, request, jsonify, send_file, Response
)
from io import BytesIO

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# *** Change this path if your TAP directory is elsewhere ***
TAP_DIR = r'C:\Users\gonca\Desktop\TAP'

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024  # 64 MB max upload

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s — %(message)s',
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Import local modules (must be in same directory)
# ---------------------------------------------------------------------------

try:
    from cp_parser import discover_all, parse_vs
    from pano_builder import build_panorama_xml, DEFAULT_INTERFACE_MAP
except ImportError as exc:
    log.error("Failed to import cp_parser / pano_builder: %s", exc)
    raise


# ---------------------------------------------------------------------------
# CORS helper (for local development)
# ---------------------------------------------------------------------------

@app.after_request
def _add_cors(response):
    response.headers['Access-Control-Allow-Origin']  = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    return response


@app.route('/api/<path:p>', methods=['OPTIONS'])
def _options(p):
    return Response(status=204)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    """Serve the main UI."""
    return render_template('index.html')


@app.route('/api/scan')
def api_scan():
    """
    Scan the TAP directory and return VS list + available packages.

    Response JSON:
    {
      "tap_dir": "...",
      "vs_list": [
        {
          "vs_id": "VS3",
          "vs_name": "VS-CLIENTES",
          "config_file": "...",
          "route_file": "...",
          "package_file": "...",
          "has_config": true,
          "has_route": true,
          "has_package": true,
        }, ...
      ],
      "all_packages": [
        {"filename": "show_package_...tar.gz", "filepath": "..."},
        ...
      ],
      "default_interface_map": {"bond1": "ae1", ...},
      "error": null
    }
    """
    try:
        vs_list, all_packages = discover_all(TAP_DIR)

        # Enrich with boolean flags and shorten paths for display
        for vs in vs_list:
            vs['has_config']  = bool(vs.get('config_file'))
            vs['has_route']   = bool(vs.get('route_file'))
            vs['has_package'] = bool(vs.get('package_file'))
            # Replace full paths with basenames for display
            for key in ('config_file', 'route_file', 'package_file'):
                if vs.get(key):
                    vs[f"{key}_basename"] = os.path.basename(vs[key])
                else:
                    vs[f"{key}_basename"] = None

        return jsonify({
            'tap_dir':               TAP_DIR,
            'vs_list':               vs_list,
            'all_packages':          all_packages,
            'default_interface_map': DEFAULT_INTERFACE_MAP,
            'error':                 None,
        })
    except Exception as exc:
        log.exception("Scan error")
        return jsonify({'error': str(exc), 'vs_list': [], 'all_packages': []}), 500


@app.route('/api/convert', methods=['POST'])
def api_convert():
    """
    Convert selected VSes to Panorama XML.

    Request JSON body:
    {
      "selected_vs": [
        {
          "vs_id": "VS3",
          "vs_name": "VS-CLIENTES",
          "config_file": "...",
          "route_file": "...",
          "package_file": "...",
        }, ...
      ],
      "interface_map": {"bond1": "ae1", "bond2": "ae2", ...},
      "options": {
        "only_referenced_objects": false,
        "prefix_object_names": false
      },
      "existing_xml": "<?xml ...>..." or null,
      "wave_label": "Wave 1"
    }

    Response JSON:
    {
      "xml_b64": "base64-encoded XML string",
      "report":  [...],
      "filename": "panorama_migration_2026-03-13.xml",
      "error": null
    }
    """
    try:
        body = request.get_json(force=True, silent=True) or {}
    except Exception:
        body = {}

    selected_vs   = body.get('selected_vs', [])
    interface_map = body.get('interface_map', None)
    options       = body.get('options', {})
    existing_xml  = body.get('existing_xml', None)
    wave_label    = body.get('wave_label', '')

    if not selected_vs:
        return jsonify({'error': 'No VS selected for conversion.'}), 400

    # Parse each selected VS
    vs_data_list = []
    parse_errors = []
    for vs_info in selected_vs:
        try:
            vs_data = parse_vs(vs_info, TAP_DIR)
            vs_data_list.append(vs_data)
        except Exception as exc:
            parse_errors.append(f"{vs_info.get('vs_name', '?')}: {exc}")
            log.exception("Parse error for %s", vs_info.get('vs_name'))

    if not vs_data_list and parse_errors:
        return jsonify({'error': 'All VS failed to parse: ' + '; '.join(parse_errors)}), 500

    # Build Panorama XML
    try:
        xml_str, report = build_panorama_xml(
            vs_data_list,
            existing_xml_str=existing_xml,
            interface_map=interface_map,
            options=options,
        )
    except Exception as exc:
        log.exception("XML build error")
        return jsonify({'error': f"XML build failed: {exc}"}), 500

    # Encode XML as base64 for JSON transport
    xml_b64 = base64.b64encode(xml_str.encode('utf-8')).decode('ascii')

    # Build filename — Panorama limits config names to 32 chars (incl. extension)
    # Max stem = 28 chars + ".xml" = 32
    date_str  = datetime.now().strftime('%m%d_%H%M')          # 9 chars
    wave_part = wave_label.replace(' ', '_')[:16] if wave_label else 'pan'
    stem      = f"{wave_part}_{date_str}"[:28]                 # hard cap at 28
    filename  = f"{stem}.xml"

    return jsonify({
        'xml_b64':  xml_b64,
        'report':   report,
        'filename': filename,
        'error':    None,
    })


@app.route('/api/download', methods=['POST'])
def api_download():
    """
    Accept a JSON body with {xml_b64, filename} and serve the file download.
    """
    try:
        body     = request.get_json(force=True, silent=True) or {}
        xml_b64  = body.get('xml_b64', '')
        filename = body.get('filename', 'panorama_migration.xml')

        xml_bytes = base64.b64decode(xml_b64)
        buf = BytesIO(xml_bytes)
        buf.seek(0)

        return send_file(
            buf,
            as_attachment=True,
            download_name=filename,
            mimetype='application/xml',
        )
    except Exception as exc:
        log.exception("Download error")
        return jsonify({'error': str(exc)}), 500


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print("=" * 60)
    print("  Check Point -> Panorama Migration Tool")
    print(f"  TAP directory: {TAP_DIR}")
    print("  Open http://localhost:5000 in your browser")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=False)
