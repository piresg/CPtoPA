"""
cp_parser.py — Check Point VSX configuration parser for migration to Panorama.

Parses:
  - show_configuration_*.txt  (interfaces, VPN tunnels)
  - show_route_*.txt          (static routes)
  - show_package_*.tar.gz     (objects, security rules, NAT rules, gateway objects)

Entry points:
  discover_all(tap_dir)      → list of VS info dicts
  parse_vs(vs_info, tap_dir) → structured VS data dict
"""

import os
import re
import json
import tarfile
import logging
from io import BytesIO

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Name sanitization
# ---------------------------------------------------------------------------

def sanitize_name(name, max_len=63):
    """
    Convert a Check Point object name to a PAN-OS compatible identifier.
    Rules:
      - Replace spaces, slashes, colons, commas, parentheses with dash
      - Remove any remaining chars not in [a-zA-Z0-9_.-]
      - Collapse multiple consecutive dashes
      - Strip leading/trailing dashes and dots
      - Prefix with 'obj-' if the result starts with a digit
      - Truncate to max_len characters
    """
    if not name:
        return "unnamed"
    s = str(name)
    # Replace common delimiters with dash
    s = re.sub(r'[\s/:\\,;()\[\]{}<>@#$%^&*+=|`~\'"]', '-', s)
    # Remove remaining illegal chars (keep a-z A-Z 0-9 _ . -)
    s = re.sub(r'[^a-zA-Z0-9_.\-]', '', s)
    # Collapse multiple dashes/dots
    s = re.sub(r'-{2,}', '-', s)
    # Strip leading/trailing dashes and dots
    s = s.strip('-.')
    if not s:
        s = "unnamed"
    # PAN names cannot start with a digit
    if s and s[0].isdigit():
        s = 'obj-' + s
    # Truncate
    return s[:max_len]


def unique_name(base, used_set):
    """Return a name that is not in used_set, appending _2, _3 etc as needed."""
    if base not in used_set:
        used_set.add(base)
        return base
    i = 2
    candidate = f"{base}_{i}"
    while candidate in used_set:
        i += 1
        candidate = f"{base}_{i}"
    used_set.add(candidate)
    return candidate


# ---------------------------------------------------------------------------
# Directory scanning / discovery
# ---------------------------------------------------------------------------

_VS_RE = re.compile(r'show_configuration_\d+_(VS\d+)_([\w\-]+)\.txt$', re.IGNORECASE)
_ROUTE_RE = re.compile(r'show_route_\d+_(VS\d+)_([\w\-]+)\.txt$', re.IGNORECASE)

# Heuristic mapping from VS name to policy package keyword
_PACKAGE_KEYWORDS = {
    'WARPDRIVE':   'WARPDRIVE',
    'VS-CLIENTES': 'CLIENTES',
    'VS-MOBILE':   'Mobile',
    'VS-WEB1':     'WEB1',
    'VS-DMZ':      'DMZ',
    'VS-ENTIDADES':'Entidades',
    'VS-INTERNET': 'Internet',
    'VS-WEBX':     'VS-WEBX',
    'VS-RBVPN':    'RBVPN',
    'VS-CPDNETS':  'CPDNETS',
    'VS-NAAS':     'NAAS',
}


def _find_packages(pkg_dir):
    """Return list of (filename, filepath) for .tar.gz files in pkg_dir."""
    packages = []
    if not pkg_dir or not os.path.isdir(pkg_dir):
        return packages
    for root, _, files in os.walk(pkg_dir):
        for f in files:
            if f.endswith('.tar.gz'):
                packages.append((f, os.path.join(root, f)))
    return packages


def _match_package(vs_name, packages):
    """Heuristically match a VS name to a package filename. Returns filepath or None."""
    keyword = _PACKAGE_KEYWORDS.get(vs_name.upper(), None)
    if keyword is None:
        # Try to derive keyword from VS name
        keyword = vs_name.replace('VS-', '').replace('-', '_')

    keyword_lower = keyword.lower()
    best = None
    for fname, fpath in packages:
        fname_lower = fname.lower()
        if keyword_lower in fname_lower:
            best = fpath
            break

    # Fallback: partial match on VS name
    if best is None:
        vs_key = vs_name.lower().replace('vs-', '').replace('-', '')
        for fname, fpath in packages:
            fname_key = fname.lower().replace('politica_', '').replace('_vsx', '')
            if vs_key in fname_key:
                best = fpath
                break

    return best


def discover_all(tap_dir):
    """
    Scan the TAP directory and return a list of VS info dicts.

    Each dict:
    {
        'vs_id':      'VS3',
        'vs_name':    'VS-CLIENTES',
        'config_file': '/path/to/show_configuration.txt',  # or None
        'route_file':  '/path/to/show_route.txt',           # or None
        'package_file': '/path/to/show_package.tar.gz',    # or None
    }
    """
    config_dir = os.path.join(tap_dir, 'Show Configuration')
    route_dir  = os.path.join(tap_dir, 'Show Route')

    # Find package dir — might be nested under "Show Package/Collected on ..."
    pkg_dir = None
    show_pkg_base = os.path.join(tap_dir, 'Show Package')
    if os.path.isdir(show_pkg_base):
        for entry in os.scandir(show_pkg_base):
            if entry.is_dir():
                pkg_dir = entry.path
                break
        if pkg_dir is None:
            pkg_dir = show_pkg_base

    packages = _find_packages(pkg_dir)

    # Build VS list from configuration files
    vs_map = {}  # vs_id → dict
    if os.path.isdir(config_dir):
        for fname in sorted(os.listdir(config_dir)):
            m = _VS_RE.match(fname)
            if m:
                vs_id, vs_name = m.group(1).upper(), m.group(2).upper()
                vs_map[vs_id] = {
                    'vs_id': vs_id,
                    'vs_name': vs_name,
                    'config_file': os.path.join(config_dir, fname),
                    'route_file': None,
                    'package_file': None,
                }

    # Match route files
    if os.path.isdir(route_dir):
        for fname in os.listdir(route_dir):
            m = _ROUTE_RE.match(fname)
            if m:
                vs_id = m.group(1).upper()
                if vs_id in vs_map:
                    vs_map[vs_id]['route_file'] = os.path.join(route_dir, fname)
                else:
                    # VS only has route file
                    vs_name = m.group(2).upper()
                    vs_map[vs_id] = {
                        'vs_id': vs_id,
                        'vs_name': vs_name,
                        'config_file': None,
                        'route_file': os.path.join(route_dir, fname),
                        'package_file': None,
                    }

    # Match packages
    for vs_id, info in vs_map.items():
        info['package_file'] = _match_package(info['vs_name'], packages)

    # Also expose all available packages for the UI to allow re-assignment
    all_packages = [{'filename': os.path.basename(fp), 'filepath': fp} for _, fp in packages]

    result = sorted(vs_map.values(), key=lambda x: (
        int(re.sub(r'\D', '', x['vs_id']) or '0'), x['vs_name']
    ))
    return result, all_packages


# ---------------------------------------------------------------------------
# show_configuration parser
# ---------------------------------------------------------------------------

def parse_configuration(filepath):
    """
    Parse a show_configuration file.

    Returns:
    {
        'vpn_tunnels': [
            {'id': 1, 'local': '100.126.0.33', 'remote': '100.64.18.25', 'peer': 'gw_LSYH1'}
        ],
        'interfaces': {
            'bond1.10': {'ip': '172.18.0.254', 'mask_len': 16},
            ...
        },
        'vlans': {                      # bond sub-interfaces declared
            'bond1': [10, 21, 22, ...],
        },
        'eth_interfaces': ['eth1-03.5', ...],
        'raw_cp_ifaces': set(),          # all CP interface names seen
        'bgp': {
            'local_as': 65500,
            'peers': [
                {
                    'peer_ip':    '169.254.54.209',
                    'remote_as':  64512,
                    'holdtime':   30,
                    'keepalive':  10,
                    'import_map': 'AWS_Tunnel_IN',
                    'export_map': 'AWS_Tunnel_OUT',
                }, ...
            ]
        } or None
    }
    """
    result = {
        'vpn_tunnels': [],
        'interfaces': {},
        'vlans': {},
        'eth_interfaces': [],
        'raw_cp_ifaces': set(),
        'bgp': None,
    }

    if not filepath or not os.path.isfile(filepath):
        return result

    vpn_re    = re.compile(
        r'^add vpn tunnel\s+(\d+)\s+type numbered\s+local\s+([\d.]+)\s+remote\s+([\d.]+)\s+peer\s+(\S+)',
        re.IGNORECASE
    )
    vlan_re   = re.compile(r'^add interface\s+(\w+)\s+vlan\s+(\d+)', re.IGNORECASE)
    ip_re     = re.compile(
        r'^set interface\s+(\S+)\s+ipv4-address\s+([\d.]+)\s+mask-length\s+(\d+)',
        re.IGNORECASE
    )
    eth_vlan_re = re.compile(r'^add interface\s+(eth[\w\-]+)\s+vlan\s+(\d+)', re.IGNORECASE)

    # BGP patterns
    bgp_as_re        = re.compile(r'^set as\s+(\d+)', re.IGNORECASE)
    bgp_peer_on_re   = re.compile(
        r'^set bgp external remote-as\s+(\d+)\s+peer\s+([\d.]+)\s+on', re.IGNORECASE
    )
    bgp_holdtime_re  = re.compile(
        r'^set bgp external remote-as\s+(\d+)\s+peer\s+([\d.]+)\s+holdtime\s+(\d+)', re.IGNORECASE
    )
    bgp_keepalive_re = re.compile(
        r'^set bgp external remote-as\s+(\d+)\s+peer\s+([\d.]+)\s+keepalive\s+(\d+)', re.IGNORECASE
    )
    bgp_export_re    = re.compile(
        r'^set bgp external remote-as\s+(\d+)\s+peer\s+([\d.]+)\s+export-routemap\s+"?([^"\s]+)"?',
        re.IGNORECASE
    )
    bgp_import_re    = re.compile(
        r'^set bgp external remote-as\s+(\d+)\s+peer\s+([\d.]+)\s+import-routemap\s+"?([^"\s]+)"?',
        re.IGNORECASE
    )
    # AS-level route-maps (apply to all peers of that AS)
    bgp_as_export_re = re.compile(
        r'^set bgp external remote-as\s+(\d+)\s+export-routemap\s+"?([^"\s]+)"?',
        re.IGNORECASE
    )
    bgp_as_import_re = re.compile(
        r'^set bgp external remote-as\s+(\d+)\s+import-routemap\s+"?([^"\s]+)"?',
        re.IGNORECASE
    )

    local_as = None
    # peers keyed by (remote_as, peer_ip)
    bgp_peers = {}        # (remote_as, peer_ip) -> dict
    bgp_as_maps = {}      # remote_as -> {'import_map': ..., 'export_map': ...}

    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as fh:
            for line in fh:
                line = line.strip()
                if line.startswith('#'):
                    continue

                m = vpn_re.match(line)
                if m:
                    result['vpn_tunnels'].append({
                        'id':     int(m.group(1)),
                        'local':  m.group(2),
                        'remote': m.group(3),
                        'peer':   m.group(4),
                    })
                    continue

                m = vlan_re.match(line)
                if m:
                    bond, vlan = m.group(1), int(m.group(2))
                    result['vlans'].setdefault(bond, []).append(vlan)
                    result['raw_cp_ifaces'].add(f"{bond}.{vlan}")
                    continue

                m = ip_re.match(line)
                if m:
                    iface, ip, mlen = m.group(1), m.group(2), int(m.group(3))
                    result['interfaces'][iface] = {'ip': ip, 'mask_len': mlen}
                    result['raw_cp_ifaces'].add(iface)
                    continue

                m = bgp_as_re.match(line)
                if m:
                    local_as = int(m.group(1))
                    continue

                m = bgp_peer_on_re.match(line)
                if m:
                    key = (int(m.group(1)), m.group(2))
                    bgp_peers.setdefault(key, {
                        'remote_as': int(m.group(1)),
                        'peer_ip':   m.group(2),
                        'holdtime':  None,
                        'keepalive': None,
                        'import_map': None,
                        'export_map': None,
                    })
                    continue

                m = bgp_holdtime_re.match(line)
                if m:
                    key = (int(m.group(1)), m.group(2))
                    bgp_peers.setdefault(key, {'remote_as': int(m.group(1)), 'peer_ip': m.group(2),
                                               'holdtime': None, 'keepalive': None,
                                               'import_map': None, 'export_map': None})
                    bgp_peers[key]['holdtime'] = int(m.group(3))
                    continue

                m = bgp_keepalive_re.match(line)
                if m:
                    key = (int(m.group(1)), m.group(2))
                    bgp_peers.setdefault(key, {'remote_as': int(m.group(1)), 'peer_ip': m.group(2),
                                               'holdtime': None, 'keepalive': None,
                                               'import_map': None, 'export_map': None})
                    bgp_peers[key]['keepalive'] = int(m.group(3))
                    continue

                m = bgp_export_re.match(line)
                if m:
                    key = (int(m.group(1)), m.group(2))
                    if key in bgp_peers:
                        bgp_peers[key]['export_map'] = m.group(3)
                    continue

                m = bgp_import_re.match(line)
                if m:
                    key = (int(m.group(1)), m.group(2))
                    if key in bgp_peers:
                        bgp_peers[key]['import_map'] = m.group(3)
                    continue

                m = bgp_as_export_re.match(line)
                if m:
                    bgp_as_maps.setdefault(int(m.group(1)), {})['export_map'] = m.group(2)
                    continue

                m = bgp_as_import_re.match(line)
                if m:
                    bgp_as_maps.setdefault(int(m.group(1)), {})['import_map'] = m.group(2)
                    continue

    except Exception as exc:
        log.warning("Error parsing configuration %s: %s", filepath, exc)

    # Apply AS-level route-maps to peers that have no peer-level route-map
    for (remote_as, peer_ip), peer in bgp_peers.items():
        as_maps = bgp_as_maps.get(remote_as, {})
        if peer['import_map'] is None and as_maps.get('import_map'):
            peer['import_map'] = as_maps['import_map']
        if peer['export_map'] is None and as_maps.get('export_map'):
            peer['export_map'] = as_maps['export_map']

    if local_as is not None or bgp_peers:
        result['bgp'] = {
            'local_as': local_as,
            'peers':    list(bgp_peers.values()),
        }

    return result


# ---------------------------------------------------------------------------
# show_route parser
# ---------------------------------------------------------------------------

def parse_routes(filepath):
    """
    Parse a show_route file and return only static routes.

    Returns list of:
    {'destination': '0.0.0.0/0', 'nexthop': '192.168.25.254', 'interface': 'eth1-03.5'}
    """
    routes = []
    if not filepath or not os.path.isfile(filepath):
        return routes

    # e.g.  S    0.0.0.0/0           via 192.168.25.254, eth1-03.5, cost 0, age 716202
    static_re = re.compile(
        r'^S\s+([\d.]+/\d+)\s+via\s+([\d.]+),\s*([\S]+)',
        re.IGNORECASE
    )

    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as fh:
            for line in fh:
                line = line.strip()
                m = static_re.match(line)
                if m:
                    iface = m.group(3).rstrip(',')
                    routes.append({
                        'destination': m.group(1),
                        'nexthop':     m.group(2),
                        'interface':   iface,
                    })
    except Exception as exc:
        log.warning("Error parsing routes %s: %s", filepath, exc)

    return routes


# ---------------------------------------------------------------------------
# Package loader
# ---------------------------------------------------------------------------

def _read_tar_member(tf, name):
    """Read a named member from an open TarFile; return parsed JSON or None."""
    try:
        member = tf.getmember(name)
        fobj   = tf.extractfile(member)
        if fobj:
            raw = fobj.read().decode('utf-8', errors='replace')
            return json.loads(raw)
    except (KeyError, json.JSONDecodeError, Exception) as exc:
        log.warning("Could not read tar member %s: %s", name, exc)
    return None


def load_package(filepath):
    """
    Load a show_package tar.gz and return structured data.

    Returns:
    {
        'objects':         [...],   # raw objects list from *_objects.json
        'gateway_objects': [...],   # raw gateway objects list
        'security_rules':  [...],   # raw access-rules + access-sections list
        'nat_rules':       [...],   # raw nat-rules + nat-sections list
        'app_rules':       [...],   # raw app-layer rules (may be empty)
        'package_name':    'Politica_CLIENTES',
        'errors':          [],
    }
    """
    data = {
        'objects': [],
        'gateway_objects': [],
        'security_rules': [],
        'nat_rules': [],
        'app_rules': [],
        'package_name': '',
        'errors': [],
    }

    if not filepath or not os.path.isfile(filepath):
        data['errors'].append(f"Package file not found: {filepath}")
        return data

    try:
        tf = tarfile.open(filepath, 'r:gz')
    except Exception as exc:
        data['errors'].append(f"Cannot open tar.gz {filepath}: {exc}")
        return data

    names = tf.getnames()
    # Derive package name from objects file name
    pkg_name = ''
    for n in names:
        if n.endswith('_objects.json') and not n.endswith('_gateway_objects.json'):
            pkg_name = os.path.basename(n).replace('_objects.json', '')
            break
    data['package_name'] = pkg_name

    for n in names:
        base = os.path.basename(n)
        if base.endswith('_objects.json') and not base.endswith('_gateway_objects.json'):
            obj = _read_tar_member(tf, n)
            if obj is not None:
                data['objects'] = obj if isinstance(obj, list) else [obj]

        elif base.endswith('_gateway_objects.json'):
            obj = _read_tar_member(tf, n)
            if obj is not None:
                data['gateway_objects'] = obj if isinstance(obj, list) else [obj]

        elif 'NAT-Management server.json' in base:
            obj = _read_tar_member(tf, n)
            if obj is not None:
                data['nat_rules'] = obj if isinstance(obj, list) else [obj]

        elif 'Application-Management server.json' in base:
            obj = _read_tar_member(tf, n)
            if obj is not None:
                data['app_rules'] = obj if isinstance(obj, list) else [obj]

        elif ('Security-Management server.json' in base
              or 'Network-Management server.json' in base):
            # CP policy layers can be named "Security" or "Network" — both are firewall rules
            obj = _read_tar_member(tf, n)
            if obj is not None:
                data['security_rules'] = obj if isinstance(obj, list) else [obj]

    # Build VPN peer map from vpn-community-star objects
    data['vpn_peer_map'] = _parse_vpn_peer_map(data.get('objects', []))

    tf.close()
    return data


def _parse_vpn_peer_map(objects):
    """
    Build a map: peer_name -> VPN info from vpn-community-star objects.

    Returns:
    {
        'gw_LSYH1': {
            'ike_peer_ip':  '40.74.20.8',
            'ike_version':  'ikev1',   # 'ikev1' | 'ikev2'
            'psk':          'secret',
            'p1': {'encryption': 'aes-256-cbc', 'hash': 'sha256', 'dh_group': 'group14',
                   'lifetime_sec': 86400},
            'p2': {'encryption': 'aes-256-cbc', 'hash': 'sha256', 'pfs_group': 'group14',
                   'lifetime_sec': 3600},
        }, ...
    }
    """
    _ENC_MAP = {
        'aes-256': 'aes-256-cbc', 'aes-128': 'aes-128-cbc',
        '3des': '3des', 'des': 'des',
        'aes-192': 'aes-192-cbc',
    }
    _HASH_MAP = {
        'sha256': 'sha256', 'sha1': 'sha1', 'sha512': 'sha512',
        'sha384': 'sha384', 'md5': 'md5',
    }
    _DH_MAP = {
        'group-1': 'group1', 'group-2': 'group2', 'group-5': 'group5',
        'group-14': 'group14', 'group-19': 'group19', 'group-20': 'group20',
        'group-24': 'group24',
    }

    peer_map = {}
    for obj in objects:
        if not isinstance(obj, dict) or obj.get('type') != 'vpn-community-star':
            continue

        enc_method = obj.get('encryption-method', '')
        ike_version = 'ikev2' if enc_method == 'ikev2 only' else 'ikev1'

        p1_raw = obj.get('ike-phase-1', {})
        p1 = {
            'encryption': _ENC_MAP.get(p1_raw.get('encryption-algorithm', ''), 'aes-256-cbc'),
            'hash':       _HASH_MAP.get(p1_raw.get('data-integrity', ''), 'sha256'),
            'dh_group':   _DH_MAP.get(p1_raw.get('diffie-hellman-group', ''), 'group14'),
            'lifetime_sec': int(p1_raw.get('ike-p1-rekey-time', 1440)) * 60,
        }

        p2_raw = obj.get('ike-phase-2', {})
        use_pfs = p2_raw.get('ike-p2-use-pfs', False)
        pfs_dh  = p2_raw.get('ike-p2-pfs-dh-grp', '')
        p2 = {
            'encryption': _ENC_MAP.get(p2_raw.get('encryption-algorithm', ''), 'aes-256-cbc'),
            'hash':       _HASH_MAP.get(p2_raw.get('data-integrity', ''), 'sha256'),
            'pfs_group':  _DH_MAP.get(pfs_dh, 'group14') if use_pfs else None,
            'lifetime_sec': int(p2_raw.get('ike-p2-rekey-time', 3600)),
        }

        for secret in obj.get('shared-secrets', []):
            gw = secret.get('external-gateway', {})
            peer_name = gw.get('name', '')
            peer_ip   = gw.get('ipv4-address', '')
            if not peer_name or not peer_ip:
                continue

            # PSK is stored in comments in various formats:
            #   "PSK=   <value>"
            #   "... PSK: <value>"
            #   "<description>   <value>"  (PSK as last token after multiple spaces)
            psk = ''
            comment = gw.get('comments', '') or ''
            if 'PSK=' in comment:
                psk = comment.split('PSK=')[-1].strip().split()[0]
            elif 'PSK:' in comment:
                psk = comment.split('PSK:')[-1].strip().split()[0]
            elif comment and ' ' not in comment and len(comment) > 12:
                # Entire comment is a single token — treat as bare PSK
                psk = comment
            elif '   ' in comment:
                # Multiple spaces before last token often indicates an unmarked PSK
                last = comment.split()[-1] if comment.split() else ''
                # Only treat as PSK if it looks like one (>12 chars, no spaces in original segment)
                if len(last) > 12 and comment.endswith(last):
                    psk = last

            peer_map[peer_name] = {
                'ike_peer_ip':  peer_ip,
                'ike_version':  ike_version,
                'psk':          psk,
                'p1':           p1,
                'p2':           p2,
                'community':    obj.get('name', ''),
            }

    return peer_map


# ---------------------------------------------------------------------------
# Full VS parse
# ---------------------------------------------------------------------------

def parse_vs(vs_info, tap_dir=None):
    """
    Parse a single VS entry (from discover_all) into a structured data dict.

    Returns:
    {
        'vs_id':      'VS3',
        'vs_name':    'VS-CLIENTES',
        'dg_name':    'DG-VS-CLIENTES',
        'tmpl_name':  'Tmpl-VS-CLIENTES',
        'vr_name':    'VR-VS-CLIENTES',
        'config':     {...},   # from parse_configuration
        'routes':     [...],   # from parse_routes
        'package':    {...},   # from load_package
        'uid_map':    {uid: obj},
        'errors':     [],
        'warnings':   [],
    }
    """
    vs_id   = vs_info.get('vs_id', 'VS0')
    vs_name = vs_info.get('vs_name', 'UNKNOWN')

    result = {
        'vs_id':     vs_id,
        'vs_name':   vs_name,
        'dg_name':   f"DG-{vs_name}",
        'tmpl_name': f"Tmpl-{vs_name}",
        'vr_name':   f"VR-{vs_name}",
        'config':    {},
        'routes':    [],
        'package':   {},
        'uid_map':   {},
        'errors':    [],
        'warnings':  [],
    }

    # Parse configuration
    config_file = vs_info.get('config_file')
    if config_file:
        try:
            result['config'] = parse_configuration(config_file)
        except Exception as exc:
            result['errors'].append(f"Configuration parse error: {exc}")
    else:
        result['warnings'].append("No show_configuration file found for this VS.")

    # Parse routes
    route_file = vs_info.get('route_file')
    if route_file:
        try:
            result['routes'] = parse_routes(route_file)
        except Exception as exc:
            result['errors'].append(f"Route parse error: {exc}")
    else:
        result['warnings'].append("No show_route file found for this VS.")

    # Load policy package
    package_file = vs_info.get('package_file')
    if package_file:
        try:
            pkg = load_package(package_file)
            result['package'] = pkg
            result['errors'].extend(pkg.get('errors', []))
        except Exception as exc:
            result['errors'].append(f"Package load error: {exc}")
    else:
        result['warnings'].append("No policy package (tar.gz) found for this VS.")

    # Build UID map
    objects = result['package'].get('objects', [])
    uid_map = {}
    for obj in objects:
        uid = obj.get('uid')
        if uid:
            uid_map[uid] = obj
    result['uid_map'] = uid_map

    # Enrich vpn_tunnels with IKE/IPSec data from VPN community objects
    vpn_peer_map = result['package'].get('vpn_peer_map', {})
    for tunnel in result['config'].get('vpn_tunnels', []):
        peer_name = tunnel.get('peer', '')
        if peer_name in vpn_peer_map:
            tunnel.update(vpn_peer_map[peer_name])

    return result
