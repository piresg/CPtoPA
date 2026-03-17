"""
pano_builder.py — Build Panorama XML from parsed Check Point VSX data.

Main entry point:
    build_panorama_xml(vs_data_list, existing_xml_str, interface_map, options)
    → (xml_string, conversion_report)

conversion_report is a list of per-VS dicts:
{
    'vs_name': str,
    'dg_name': str,
    'tmpl_name': str,
    'objects_converted': {'host': N, 'network': N, ...},
    'rules_converted': {'security': N, 'nat': N},
    'vpn_tunnels': N,
    'interfaces': N,
    'warnings': [str, ...],
    'errors': [str, ...],
    'skipped': bool,   # True if DG/Template already existed in the merge target
}
"""

import re
import ipaddress
import logging
from xml.etree import ElementTree as ET
from xml.dom import minidom

from cp_parser import sanitize_name, unique_name

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants / well-known CP UIDs
# ---------------------------------------------------------------------------

# CP "Any" object
_ANY_UID_NAMES = {'CpmiAnyObject', 'any'}

# CP policy-targets pseudo-UID
_POLICY_TARGETS_NAME = 'Policy Targets'

# Action mapping
_ACTION_MAP = {
    'accept': 'allow',
    'allow':  'allow',
    'drop':   'deny',
    'reject': 'deny',
    'inner layer': 'allow',
}

# Encryption algorithm mapping CP → PAN
_ENC_MAP = {
    'aes-128': 'aes-128-cbc',
    'aes-256': 'aes-256-cbc',
    '3des':    '3des',
    'aes-128-gcm': 'aes-128-gcm',
    'aes-256-gcm': 'aes-256-gcm',
}

# Hash / integrity mapping
_HASH_MAP = {
    'sha1':   'sha1',
    'sha256': 'sha256',
    'sha384': 'sha384',
    'sha512': 'sha512',
    'md5':    'md5',
}

# DH group mapping
_DH_MAP = {
    'group-1':  'group1',
    'group-2':  'group2',
    'group-5':  'group5',
    'group-14': 'group14',
    'group-19': 'group19',
    'group-20': 'group20',
    'group 1':  'group1',
    'group 2':  'group2',
    'group 5':  'group5',
    'group 14': 'group14',
}

# ---------------------------------------------------------------------------
# CP service → PAN Application-ID mappings
# ---------------------------------------------------------------------------

# ICMP type number → PAN App-ID
_ICMP_TYPE_TO_APPID = {
    0:  'ping',          # echo-reply
    3:  'icmp',          # destination-unreachable
    4:  'icmp',          # source-quench
    5:  'icmp',          # redirect
    8:  'ping',          # echo-request
    9:  'icmp',          # router-advertisement
    10: 'icmp',          # router-solicitation
    11: 'icmp',          # time-exceeded (used by traceroute)
    12: 'icmp',          # parameter-problem
    13: 'icmp',          # timestamp
    14: 'icmp',          # timestamp-reply
    15: 'icmp',          # info-request
    16: 'icmp',          # info-reply
    17: 'icmp',          # mask-request
    18: 'icmp',          # mask-reply
    30: 'traceroute',    # traceroute
}

# IP protocol number → PAN App-ID
_IPROTO_TO_APPID = {
    2:   'igmp',
    4:   'ipip',         # IP-in-IP encapsulation
    41:  'ipv6',         # IPv6 encapsulation
    47:  'gre',
    50:  'ipsec-esp',
    51:  'ipsec-ah',
    89:  'ospf',
    103: 'pim-sm',
    112: 'vrrp',
}

# Well-known CP service-other names → PAN App-ID (used when ip-protocol is absent/unclear)
_CP_NAME_TO_APPID = {
    'ah':                'ipsec-ah',
    'esp':               'ipsec-esp',
    'gre':               'gre',
    'igmp':              'igmp',
    'ospf':              'ospf',
    'vrrp':              'vrrp',
    'traceroute':        'traceroute',
    'dhcp-request':      'dhcp',
    'dhcp-reply':        'dhcp',
    'ftp_mapped':        'ftp',
    'sip_dynamic_ports': 'sip',
    'icmp-proto':        'icmp',
}

# Sentinel prefix used to encode app-id in the uid→pan map without polluting service lists
_APPID_SENTINEL = '__appid__:'


def _appid_sentinel(appid):
    return f"{_APPID_SENTINEL}{appid}"


def _is_appid_sentinel(s):
    return isinstance(s, str) and s.startswith(_APPID_SENTINEL)


def _appid_from_sentinel(s):
    return s[len(_APPID_SENTINEL):]


def _cp_obj_to_appid(obj):
    """Derive the best PAN App-ID string for a service-icmp or service-other CP object."""
    obj_type = obj.get('type', '')
    name_lower = obj.get('name', '').lower()

    if obj_type == 'service-icmp':
        itype = obj.get('icmp-type')
        if itype is not None:
            return _ICMP_TYPE_TO_APPID.get(int(itype), 'icmp')
        return 'icmp'

    if obj_type == 'service-other':
        # Try ip-protocol number first
        ip_proto = obj.get('ip-protocol')
        if ip_proto is not None:
            appid = _IPROTO_TO_APPID.get(int(ip_proto))
            if appid:
                return appid
        # Fall back to name-based lookup
        for key, appid in _CP_NAME_TO_APPID.items():
            if key in name_lower:
                return appid
        return 'any'  # unknown protocol — safest fallback

    return 'any'


# Default interface mapping CP name prefix → PAN name prefix
DEFAULT_INTERFACE_MAP = {
    'bond1':  'ae1',
    'bond2':  'ae2',
    'bond10': 'ae3',
}
# Regex for eth interfaces: ethX-YZ → ethernetX/Y
_ETH_RE = re.compile(r'^eth(\d+)-(\d+)$', re.IGNORECASE)


def _map_interface(cp_iface, iface_map):
    """
    Translate a CP interface name to a PAN interface name.
    iface_map: {cp_prefix: pan_prefix, ...}  (e.g. {'bond1': 'ae1'})
    Returns PAN interface name string.
    """
    # VLAN sub-interface: bond1.10 → ae1.10
    dot_pos = cp_iface.find('.')
    if dot_pos != -1:
        base  = cp_iface[:dot_pos]
        vlan  = cp_iface[dot_pos:]        # ".10"
        pan   = iface_map.get(base)
        if pan is None:
            pan = _map_base_iface(base, iface_map)
        return f"{pan}{vlan}" if pan else cp_iface
    else:
        pan = iface_map.get(cp_iface)
        if pan is None:
            pan = _map_base_iface(cp_iface, iface_map)
        return pan if pan else cp_iface


def _map_base_iface(cp_base, iface_map):
    """Map a base interface name (no VLAN suffix)."""
    if cp_base in iface_map:
        return iface_map[cp_base]
    m = _ETH_RE.match(cp_base)
    if m:
        return f"ethernet{m.group(1)}/{int(m.group(2))}"  # strip leading zeros
    return None


def _mask_len_to_dotted(mask_len):
    """Convert prefix length to dotted decimal mask string."""
    try:
        ml = int(mask_len)
        bits = (0xFFFFFFFF >> (32 - ml)) << (32 - ml)
        return '.'.join([str((bits >> (8 * i)) & 0xFF) for i in reversed(range(4))])
    except Exception:
        return '255.255.255.0'


# ---------------------------------------------------------------------------
# XML helpers
# ---------------------------------------------------------------------------

def _sub(parent, tag, text=None):
    """Create a sub-element, optionally with text content."""
    el = ET.SubElement(parent, tag)
    if text is not None:
        el.text = str(text)
    return el


def _member(parent, value):
    """Append a <member>value</member> to parent."""
    m = ET.SubElement(parent, 'member')
    m.text = str(value)
    return m


def _entry(parent, name):
    """Create <entry name="..."> under parent."""
    el = ET.SubElement(parent, 'entry')
    el.set('name', name)
    return el


# ---------------------------------------------------------------------------
# UID resolver
# ---------------------------------------------------------------------------

class UIDResolver:
    """Resolve CP UIDs to PAN names and build a warnings list."""

    def __init__(self, uid_map, name_registry, vs_name, warnings):
        """
        uid_map:       {uid: cp_object}
        name_registry: shared set of already-used sanitized names (per DG)
        vs_name:       used for warning messages
        warnings:      list to append warning strings to
        """
        self._uid_map   = uid_map
        self._registry  = name_registry
        self._vs        = vs_name
        self._warnings  = warnings
        # cache uid → sanitized name
        self._cache = {}

    def obj_for_uid(self, uid):
        return self._uid_map.get(uid)

    def name_for_uid(self, uid, fallback=None):
        """Return sanitized PAN name for a CP UID, or fallback."""
        if uid in self._cache:
            return self._cache[uid]
        obj = self._uid_map.get(uid)
        if obj is None:
            name = sanitize_name(fallback or uid)
            self._warnings.append(
                f"UID {uid!r} not found in objects; using name {name!r}"
            )
            self._cache[uid] = name
            return name
        obj_type = obj.get('type', '')
        obj_name = obj.get('name', uid)
        # CpmiAnyObject → 'any'
        if obj_type == 'CpmiAnyObject' or obj_name.lower() == 'any':
            self._cache[uid] = 'any'
            return 'any'
        name = sanitize_name(obj_name)
        self._cache[uid] = name
        return name

    def is_any(self, uid):
        obj = self._uid_map.get(uid)
        if obj is None:
            return False
        obj_type = obj.get('type', '')
        obj_name = obj.get('name', '').lower()
        return obj_type == 'CpmiAnyObject' or obj_name == 'any'

    def action_for_uid(self, uid):
        """Return PAN action string ('allow'/'deny') for an action UID."""
        obj = self._uid_map.get(uid)
        if obj is None:
            return 'allow'
        name = obj.get('name', 'Accept').lower()
        return _ACTION_MAP.get(name, 'allow')

    def is_gateway_type(self, uid):
        """Return True if this UID refers to a gateway/cluster object."""
        obj = self._uid_map.get(uid)
        if obj is None:
            return False
        t = obj.get('type', '')
        return t in (
            'CpmiVsClusterNetobj', 'CpmiVsxClusterNetobj',
            'simple-cluster', 'interop', 'checkpoint-host',
        )

    def is_identity_type(self, uid):
        """Return True if this UID refers to a CP identity/user object (access-role etc.)."""
        obj = self._uid_map.get(uid)
        if obj is None:
            return False
        return obj.get('type', '') in ('access-role', 'LegacyUserAtLocation')

    def name_of(self, uid):
        """Return the raw CP name for a UID (unsanitized)."""
        obj = self._uid_map.get(uid)
        return obj.get('name', '') if obj else ''

    def identity_dns(self, uid):
        """
        For an access-role / LegacyUserAtLocation UID, return a list of
        lowercase LDAP DNs or sanitized names suitable for <source-user>.
        """
        obj = self._uid_map.get(uid)
        if obj is None:
            return []

        obj_type = obj.get('type', '')

        # access-role: extract DNs from embedded users/groups list
        if obj_type == 'access-role':
            dns = []
            for entry in obj.get('users', []):
                if not isinstance(entry, dict):
                    continue
                dn = entry.get('dn', '')
                if dn:
                    dns.append(dn.lower())
            if not dns:
                name = obj.get('name', '')
                if name:
                    dns.append(sanitize_name(name))
            return dns

        # LegacyUserAtLocation: try to resolve the userGroup UID for a DN;
        # fall back to the group name (strip @Location suffix)
        if obj_type == 'LegacyUserAtLocation':
            ug_uid = obj.get('userGroup', '')
            if ug_uid:
                ug_obj = self._uid_map.get(ug_uid)
                if ug_obj:
                    dn = ug_obj.get('dn', '')
                    if dn:
                        return [dn.lower()]
            # fallback: strip @Location suffix and sanitize
            name = obj.get('name', '')
            group_part = name.split('@')[0] if '@' in name else name
            return [sanitize_name(group_part)] if group_part else [sanitize_name(name)]

        # generic fallback
        name = obj.get('name', '')
        return [sanitize_name(name)] if name else []


# ---------------------------------------------------------------------------
# Object builders
# ---------------------------------------------------------------------------

def _build_address_objects(objects, uid_map, used_names, warnings):
    """
    Build a list of (pan_name, xml_element) for address objects.
    Returns: {uid: pan_name}, [ET.Element address entry, ...]
    """
    uid_to_pan = {}
    entries = []

    for obj in objects:
        obj_type = obj.get('type', '')
        uid  = obj.get('uid', '')
        name = obj.get('name', uid)

        if obj_type == 'CpmiAnyObject':
            uid_to_pan[uid] = 'any'
            continue

        pan_name = unique_name(sanitize_name(name), used_names)
        uid_to_pan[uid] = pan_name
        entry = ET.Element('entry')
        entry.set('name', pan_name)

        if obj_type == 'host':
            ip = obj.get('ipv4-address', '')
            if ip:
                _sub(entry, 'ip-netmask', f"{ip}/32")
            else:
                warnings.append(f"Host {name!r} has no ipv4-address; skipping.")
                continue

        elif obj_type == 'network':
            subnet  = obj.get('subnet4', '')
            mask_l  = obj.get('mask-length4', 32)
            if subnet:
                _sub(entry, 'ip-netmask', f"{subnet}/{mask_l}")
            else:
                warnings.append(f"Network {name!r} has no subnet4; skipping.")
                continue

        elif obj_type == 'address-range':
            first = obj.get('ipv4-address-first', '')
            last  = obj.get('ipv4-address-last', '')
            if first and last:
                _sub(entry, 'ip-range', f"{first}-{last}")
            else:
                warnings.append(f"Address-range {name!r} missing first/last; skipping.")
                continue

        elif obj_type == 'dns-domain':
            domain = name  # CP dns-domain: name IS the domain, e.g. ".example.com"
            fqdn = domain.lstrip('.')
            _sub(entry, 'fqdn', fqdn)

        elif obj_type == 'updatable-object':
            # CP cloud-managed dynamic IP list (e.g. Microsoft Defender, Office 365).
            # PAN equivalent is an External Dynamic List (EDL) — create a placeholder
            # network entry so rule references resolve. Admin must replace with a real EDL.
            _sub(entry, 'ip-netmask', '0.0.0.0/0')
            desc = obj.get('comments', '') or obj.get('name-in-data-center', '')
            _sub(entry, 'description',
                 f"PLACEHOLDER: CP updatable-object '{name}'. Replace with PAN EDL. {desc}"[:1023])
            warnings.append(
                f"Updatable object {name!r} converted to placeholder 0.0.0.0/0 — "
                f"replace with an External Dynamic List in PAN-OS."
            )

        else:
            # Not an address type we handle
            continue

        desc = obj.get('comments', '')
        if desc:
            _sub(entry, 'description', desc[:1023])

        entries.append((uid, pan_name, entry))

    return uid_to_pan, entries


def _build_address_groups(objects, uid_to_pan, used_names, warnings):
    """Build address-group entries. Returns {uid: pan_name}, [entries]."""
    uid_to_pan_grp = {}
    entries = []

    for obj in objects:
        if obj.get('type') != 'group':
            continue
        uid  = obj.get('uid', '')
        name = obj.get('name', uid)
        pan_name = unique_name(sanitize_name(name), used_names)
        uid_to_pan_grp[uid] = pan_name

        entry = ET.Element('entry')
        entry.set('name', pan_name)
        members_el = _sub(entry, 'static')
        for member_uid in obj.get('members', []):
            member_pan = uid_to_pan.get(member_uid) or uid_to_pan_grp.get(member_uid)
            if member_pan and member_pan != 'any':
                _member(members_el, member_pan)
            # else: member not yet resolved (forward-ref groups) — skip silently
        desc = obj.get('comments', '')
        if desc:
            _sub(entry, 'description', desc[:1023])
        entries.append((uid, pan_name, entry))

    return uid_to_pan_grp, entries


def _normalize_port(port_str):
    """
    Convert a CP port expression to a PAN-OS compatible port string.
    CP supports '>N' (above N), '<N' (below N), 'Any', ranges, and single ports.
    PAN-OS supports: single (80), range (1024-65535), list (80,443).
    Returns normalized string, or None if the port should be omitted (any port).
    """
    p = str(port_str).strip()
    if not p:
        return None
    pl = p.lower()
    if pl in ('any', 'all', '*'):
        return '0-65535'
    m = re.match(r'^>(\d+)$', p)
    if m:
        lo = int(m.group(1)) + 1
        return f'{lo}-65535' if lo <= 65535 else None
    m = re.match(r'^<(\d+)$', p)
    if m:
        hi = int(m.group(1)) - 1
        return f'1-{hi}' if hi >= 1 else None
    # Already valid PAN format (digits, commas, hyphens)
    if re.match(r'^\d[\d,\-]*$', p):
        return p
    return None  # unrecognised — omit port


def _build_service_objects(objects, uid_to_pan, used_names, warnings):
    """Build service objects and service groups. Returns {uid: pan_name}, [entries]."""
    svc_uid_to_pan = {}
    svc_entries    = []
    grp_uid_to_pan = {}
    grp_entries    = []

    for obj in objects:
        obj_type = obj.get('type', '')
        uid  = obj.get('uid', '')
        name = obj.get('name', uid)

        if obj_type == 'CpmiAnyObject':
            svc_uid_to_pan[uid] = 'any'
            continue

        if obj_type in ('service-tcp', 'service-udp'):
            pan_name = unique_name(sanitize_name(name), used_names)
            svc_uid_to_pan[uid] = pan_name
            entry = ET.Element('entry')
            entry.set('name', pan_name)
            proto = 'tcp' if obj_type == 'service-tcp' else 'udp'
            protocol_el = _sub(entry, 'protocol')
            proto_el = _sub(protocol_el, proto)
            port = _normalize_port(obj.get('port', ''))
            if port:
                _sub(proto_el, 'port', port)
            else:
                _sub(proto_el, 'port', '0-65535')  # PAN requires port; default to all ports
            desc = obj.get('comments', '')
            if desc:
                _sub(entry, 'description', desc[:1023])
            svc_entries.append((uid, pan_name, entry))

        elif obj_type == 'service-icmp':
            # PAN-OS has no ICMP service objects — ICMP is matched via Application-ID.
            # Store a sentinel so the rule builder can extract the app-id.
            appid = _cp_obj_to_appid(obj)
            svc_uid_to_pan[uid] = _appid_sentinel(appid)

        elif obj_type == 'service-other':
            # IP protocol services (GRE/ESP/AH/IGMP etc.) are not PAN service objects.
            # Store a sentinel so the rule builder can extract the app-id.
            appid = _cp_obj_to_appid(obj)
            svc_uid_to_pan[uid] = _appid_sentinel(appid)

        elif obj_type == 'service-group':
            pan_name = unique_name(sanitize_name(name), used_names)
            entry = ET.Element('entry')
            entry.set('name', pan_name)
            members_el = _sub(entry, 'members')
            valid_members = []
            sentinel_appids = []
            for m_uid in obj.get('members', []):
                m_pan = svc_uid_to_pan.get(m_uid) or grp_uid_to_pan.get(m_uid)
                if not m_pan or m_pan == 'any':
                    continue
                if _is_appid_sentinel(m_pan):
                    # ICMP/other member — collect its app-id
                    sentinel_appids.append(_appid_from_sentinel(m_pan))
                else:
                    valid_members.append(m_pan)
            if valid_members:
                for m in valid_members:
                    _member(members_el, m)
                grp_uid_to_pan[uid] = pan_name
                grp_entries.append((uid, pan_name, entry))
            elif sentinel_appids:
                # Group contained only ICMP/other — encode all app-ids as a combined sentinel
                combined = ','.join(sorted(set(sentinel_appids)))
                svc_uid_to_pan[uid] = _appid_sentinel(combined)
            else:
                # Empty group — treat as any
                svc_uid_to_pan[uid] = 'any'

    return svc_uid_to_pan, svc_entries, grp_uid_to_pan, grp_entries


# ---------------------------------------------------------------------------
# Section tracker for rule tagging
# ---------------------------------------------------------------------------

def _build_section_map(rules_list):
    """
    Build a map: rule_number → section_name from access-sections.
    Sections have 'from' and 'to' rule numbers (1-based, inclusive).
    """
    section_map = {}
    for item in rules_list:
        if item.get('type') == 'access-section':
            frm = item.get('from')
            to  = item.get('to')
            sec_name = item.get('name', '')
            if frm is not None and to is not None and sec_name:
                for n in range(int(frm), int(to) + 1):
                    section_map[n] = sec_name
    return section_map


# ---------------------------------------------------------------------------
# Security rules builder
# ---------------------------------------------------------------------------

def _build_zone_map(iface_data, iface_map):
    """
    Build a list of (zone_name, IPv4Network) from interface data.
    zone_name matches what _build_template creates (cp_iface with dots→hyphens).
    """
    zones = []
    for cp_iface, info in iface_data.items():
        ip  = info.get('ip', '')
        ml  = info.get('mask_len', 24)
        if not ip:
            continue
        try:
            net = ipaddress.IPv4Network(f"{ip}/{ml}", strict=False)
            zone_name = cp_iface.replace('.', '-')
            zones.append((zone_name, net))
        except ValueError:
            pass
    return zones


def _zones_for_uids(uids, uid_map, zone_map, depth=0):
    """
    Given a list of address UIDs, return the set of zone names whose
    subnet contains at least one of the resolved addresses.
    Returns {'any'} if any UID is CpmiAnyObject or unresolvable.
    """
    if depth > 5:
        return set()
    result = set()
    for uid in uids:
        obj = uid_map.get(uid)
        if obj is None:
            continue
        obj_type = obj.get('type', '')
        if obj_type == 'CpmiAnyObject' or obj.get('name', '').lower() == 'any':
            return {'any'}
        if obj_type in ('group', 'service-group'):
            sub = _zones_for_uids(obj.get('members', []), uid_map, zone_map, depth + 1)
            if 'any' in sub:
                return {'any'}
            result |= sub
        elif obj_type == 'host':
            ip_str = obj.get('ipv4-address', '') or obj.get('ip-address', '')
            if ip_str:
                try:
                    addr = ipaddress.IPv4Address(ip_str)
                    for zname, znet in zone_map:
                        if addr in znet:
                            result.add(zname)
                except ValueError:
                    pass
        elif obj_type == 'network':
            ip_str  = obj.get('subnet4', '') or obj.get('network', '')
            mask    = obj.get('mask-length4', obj.get('subnet-mask', ''))
            if ip_str:
                try:
                    if mask and not str(mask).startswith('/'):
                        net = ipaddress.IPv4Network(f"{ip_str}/{mask}", strict=False)
                    elif mask:
                        net = ipaddress.IPv4Network(f"{ip_str}{mask}", strict=False)
                    else:
                        net = ipaddress.IPv4Network(ip_str, strict=False)
                    for zname, znet in zone_map:
                        if net.overlaps(znet):
                            result.add(zname)
                except ValueError:
                    pass
        elif obj_type == 'address-range':
            ip_first = obj.get('ipv4-address-first', '')
            if ip_first:
                try:
                    addr = ipaddress.IPv4Address(ip_first)
                    for zname, znet in zone_map:
                        if addr in znet:
                            result.add(zname)
                except ValueError:
                    pass
    return result


def _build_security_rules(rules_list, resolver, used_rule_names, warnings, zone_map=None):
    """
    Build PAN security rule XML entries.
    Returns (list of ET.Element, set of tag names used).
    """
    entries = []
    used_tags = set()
    section_map = _build_section_map(rules_list)

    for item in rules_list:
        if item.get('type') != 'access-rule':
            continue
        if not item.get('enabled', True):
            continue

        uid      = item.get('uid', '')
        rule_num = item.get('rule-number', 0)
        raw_name = item.get('name', '') or f"Rule-{rule_num}"
        pan_name = unique_name(sanitize_name(raw_name) or f"rule-{rule_num}", used_rule_names)

        entry = ET.Element('entry')
        entry.set('name', pan_name)

        # From / To zones — derive from source/destination address subnets
        srcs = item.get('source', [])
        dsts = item.get('destination', [])

        from_el = _sub(entry, 'from')
        to_el   = _sub(entry, 'to')
        if zone_map:
            src_zones = _zones_for_uids(srcs, resolver._uid_map, zone_map)
            dst_zones = _zones_for_uids(dsts, resolver._uid_map, zone_map)
            src_zones = src_zones or {'any'}
            dst_zones = dst_zones or {'any'}
        else:
            src_zones = {'any'}
            dst_zones = {'any'}
        for z in sorted(src_zones):
            _member(from_el, z)
        for z in sorted(dst_zones):
            _member(to_el, z)

        # Source
        src_el = _sub(entry, 'source')
        srcs = item.get('source', [])
        src_users = []  # CP identity/access-role objects → PAN source-user
        if not srcs or all(resolver.is_any(u) for u in srcs):
            _member(src_el, 'any')
        else:
            added = False
            for uid_s in srcs:
                if resolver.is_gateway_type(uid_s):
                    continue
                if resolver.is_identity_type(uid_s):
                    src_users.extend(resolver.identity_dns(uid_s))
                    continue
                n = resolver.name_for_uid(uid_s)
                _member(src_el, n if n != 'any' else 'any')
                added = True
            if not added:
                _member(src_el, 'any')
        if item.get('source-negate'):
            _sub(entry, 'negate-source', 'yes')
        if src_users:
            su_el = _sub(entry, 'source-user')
            for su in src_users:
                _member(su_el, su)

        # Destination
        dst_el = _sub(entry, 'destination')
        dsts = item.get('destination', [])
        if not dsts or all(resolver.is_any(u) for u in dsts):
            _member(dst_el, 'any')
        else:
            added = False
            for uid_d in dsts:
                if resolver.is_gateway_type(uid_d) or resolver.is_identity_type(uid_d):
                    continue  # identity/gateway objects are not valid destination addresses
                n = resolver.name_for_uid(uid_d)
                _member(dst_el, n if n != 'any' else 'any')
                added = True
            if not added:
                _member(dst_el, 'any')
        if item.get('destination-negate'):
            _sub(entry, 'negate-destination', 'yes')

        # Service + Application
        # CP security layer has no App-ID. However, service-icmp and service-other
        # are stored as sentinels (__appid__:<name>) and must go into <application>,
        # while real TCP/UDP services stay in <service>.
        svcs = item.get('service', [])
        real_svcs = []    # TCP/UDP service names for <service>
        appid_names = []  # PAN App-IDs to inject into <application>

        if not svcs or all(resolver.is_any(u) for u in svcs):
            real_svcs = ['any']
        else:
            for uid_sv in svcs:
                n = resolver.name_for_uid(uid_sv)
                if _is_appid_sentinel(n):
                    # One or more app-ids encoded in the sentinel (comma-separated for groups)
                    for aid in _appid_from_sentinel(n).split(','):
                        aid = aid.strip()
                        if aid and aid != 'any':
                            appid_names.append(aid)
                elif n == 'any':
                    real_svcs.append('any')
                else:
                    real_svcs.append(n)

        # If we only have app-ids and no real services, use application-default
        if not real_svcs and appid_names:
            real_svcs = ['application-default']
        elif not real_svcs:
            real_svcs = ['any']

        app_el = _sub(entry, 'application')
        if appid_names:
            seen_apps = set()
            for aid in appid_names:
                if aid not in seen_apps:
                    _member(app_el, aid)
                    seen_apps.add(aid)
        else:
            _member(app_el, 'any')

        svc_el = _sub(entry, 'service')
        seen_svcs = set()
        for sn in real_svcs:
            if sn not in seen_svcs:
                _member(svc_el, sn)
                seen_svcs.add(sn)

        if item.get('service-negate'):
            _sub(entry, 'negate-service', 'yes')

        # Action
        action_uid = item.get('action', '')
        action = resolver.action_for_uid(action_uid) if action_uid else 'allow'
        _sub(entry, 'action', action)

        # Logging
        track = item.get('track', {})
        if isinstance(track, dict):
            # Log if track type is not 'None'
            track_uid  = track.get('type', '')
            track_obj  = resolver.obj_for_uid(track_uid) if track_uid else None
            track_name = (track_obj.get('name', '') if track_obj else '').lower()
            if track_name not in ('none', ''):
                log_el = _sub(entry, 'log-setting')  # placeholder
                _sub(entry, 'log-end', 'yes')
            else:
                _sub(entry, 'log-end', 'no')
        else:
            _sub(entry, 'log-end', 'yes')

        # Description / comments
        comment = item.get('comments', '')
        if comment:
            _sub(entry, 'description', comment[:1023])

        # Tags for section membership
        sec_name = section_map.get(int(rule_num), '')
        if sec_name:
            pan_tag = sanitize_name(sec_name)[:63]
            tag_el = _sub(entry, 'tag')
            _member(tag_el, pan_tag)
            used_tags.add(pan_tag)

        entries.append(entry)

    return entries, used_tags


# ---------------------------------------------------------------------------
# NAT rules builder
# ---------------------------------------------------------------------------

_ORIGINAL_SENTINEL = {'97aeb369-9aea-11d5-bd16-0090272ccb30'}  # CP "Any" for NAT


def _nat_field(uid, resolver):
    """Resolve a NAT field UID to PAN address name, 'any', or 'original' (no translation)."""
    if not uid or uid == 'original':
        return 'original'
    obj = resolver.obj_for_uid(uid)
    if obj is not None:
        # CP 'Global' type with name 'Original' means "keep original address" — no translation
        if obj.get('type') == 'Global' or obj.get('name', '').lower() == 'original':
            return 'original'
        # Gateway/cluster objects are not valid PAN-OS address objects — skip translation
        if resolver.is_gateway_type(uid):
            return 'original'
        # FQDN (dns-domain) objects are not valid in NAT translated-address fields
        if obj.get('type') == 'dns-domain':
            return 'original'
    if resolver.is_any(uid):
        return 'any'
    return resolver.name_for_uid(uid)


def _build_nat_rules(nat_list, resolver, used_rule_names, warnings, zone_map=None):
    """
    Build PAN NAT rule entries.
    Returns list of ET.Element.
    """
    entries = []
    for item in nat_list:
        if item.get('type') != 'nat-rule':
            continue
        if not item.get('enabled', True):
            continue

        uid      = item.get('uid', '')
        rule_num = item.get('rule-number', 0)
        raw_name = item.get('name', '') or f"NAT-Rule-{rule_num}"
        pan_name = unique_name(sanitize_name(raw_name) or f"nat-{rule_num}", used_rule_names)

        entry = ET.Element('entry')
        entry.set('name', pan_name)

        srcs_uid = item.get('original-source', '')
        dsts_uid = item.get('original-destination', '')
        # Normalise to lists for zone lookup; skip 'any', sentinel values, and identity objects
        srcs_list = ([srcs_uid]
                     if srcs_uid and srcs_uid != 'original'
                     and not resolver.is_any(srcs_uid)
                     and not resolver.is_identity_type(srcs_uid)
                     else [])
        dsts_list = ([dsts_uid]
                     if dsts_uid and dsts_uid != 'original'
                     and not resolver.is_any(dsts_uid)
                     and not resolver.is_identity_type(dsts_uid)
                     else [])

        # From zone — derive from original-source addresses
        from_el = _sub(entry, 'from')
        if zone_map and srcs_list:
            src_zones = _zones_for_uids(srcs_list, resolver._uid_map, zone_map)
            if src_zones:
                for z in src_zones:
                    _member(from_el, z)
            else:
                _member(from_el, 'any')
        else:
            _member(from_el, 'any')

        # To zone — derive from original-destination addresses
        to_el = _sub(entry, 'to')
        if zone_map and dsts_list:
            dst_zones = _zones_for_uids(dsts_list, resolver._uid_map, zone_map)
            if dst_zones:
                for z in dst_zones:
                    _member(to_el, z)
            else:
                _member(to_el, 'any')
        else:
            _member(to_el, 'any')

        # Original fields
        orig_src_uid = item.get('original-source', '')
        orig_dst_uid = item.get('original-destination', '')

        # Identity and gateway objects are not valid NAT address fields — treat as 'any'
        if orig_src_uid and (resolver.is_identity_type(orig_src_uid)
                             or resolver.is_gateway_type(orig_src_uid)):
            orig_src_uid = ''
        if orig_dst_uid and (resolver.is_identity_type(orig_dst_uid)
                             or resolver.is_gateway_type(orig_dst_uid)):
            orig_dst_uid = ''

        orig_src = _nat_field(orig_src_uid, resolver)
        orig_dst = _nat_field(orig_dst_uid, resolver)
        orig_svc = item.get('original-service', '')
        if orig_svc == 'original' or resolver.is_any(orig_svc):
            orig_svc_pan = 'any'
        else:
            orig_svc_pan = resolver.name_for_uid(orig_svc) if orig_svc else 'any'

        src_el = _sub(entry, 'source')
        _member(src_el, orig_src if orig_src not in ('original',) else 'any')
        dst_el = _sub(entry, 'destination')
        _member(dst_el, orig_dst if orig_dst not in ('original',) else 'any')
        _sub(entry, 'service', orig_svc_pan)

        # Translated fields
        method = item.get('method', 'static')

        trans_src_uid = item.get('translated-source', '')
        trans_dst_uid = item.get('translated-destination', '')
        trans_src = _nat_field(trans_src_uid, resolver) if trans_src_uid else 'original'
        trans_dst = _nat_field(trans_dst_uid, resolver) if trans_dst_uid else 'original'

        # Source translation — skip if 'original' or 'any'
        if trans_src not in ('original', 'any'):
            src_xlat_el = _sub(entry, 'source-translation')
            if method == 'hide':
                dip_el = _sub(src_xlat_el, 'dynamic-ip-and-port')
                xlat_src_el = _sub(dip_el, 'translated-address')
                _member(xlat_src_el, trans_src)
            else:
                si_el = _sub(src_xlat_el, 'static-ip')
                _sub(si_el, 'translated-address', trans_src)

        # Destination translation — skip if 'original' or 'any'
        if trans_dst not in ('original', 'any'):
            dst_xlat_el = _sub(entry, 'destination-translation')
            _sub(dst_xlat_el, 'translated-address', trans_dst)

        # Description
        comment = item.get('comments', '')
        if comment:
            _sub(entry, 'description', comment[:1023])

        entries.append(entry)

    return entries


# ---------------------------------------------------------------------------
# Template builder (interfaces + routes + VPN)
# ---------------------------------------------------------------------------

def _build_template(vs_data, iface_map, warnings):
    """
    Build a Panorama template ET.Element for the VS.

    Returns ET.Element  <entry name="Tmpl-...">
    """
    tmpl_name = vs_data['tmpl_name']
    vr_name   = vs_data['vr_name']
    config    = vs_data.get('config', {})
    routes    = vs_data.get('routes', [])

    tmpl_entry = ET.Element('entry')
    tmpl_entry.set('name', tmpl_name)

    config_el   = _sub(tmpl_entry, 'config')
    devices_el  = _sub(config_el, 'devices')
    dev_entry   = _sub(devices_el, 'entry')
    dev_entry.set('name', 'localhost.localdomain')
    network_el  = _sub(dev_entry, 'network')

    # ---- Interfaces ----
    ifaces_el = _sub(network_el, 'interface')

    cp_ifaces = config.get('interfaces', {})   # {cp_iface: {ip, mask_len}}
    gateway_ifaces = []
    pkg = vs_data.get('package', {})
    gw_objs = pkg.get('gateway_objects', [])
    if gw_objs:
        # Use gateway_objects as authoritative interface list
        gw = gw_objs[0]
        gateway_ifaces = gw.get('interfaces', [])

    # Build interface data exclusively from gateway_objects when available.
    # show_configuration contains ALL interfaces from the entire VSX appliance
    # (VPN bearer VLANs for every VS), so it must NOT be used as a fallback —
    # it would flood this VS template with hundreds of wrong interfaces.
    # Only fall back to show_configuration when gateway_objects has no interfaces at all.
    iface_data = {}  # {cp_iface_name: {ip, mask_len}}
    if gateway_ifaces:
        for gi in gateway_ifaces:
            iname = gi.get('interface-name', '')
            ip    = gi.get('ipv4-address', '')
            ml    = gi.get('ipv4-mask-length', 24)
            # Skip CP VPN tunnel pseudo-interfaces (vpntN) — these are CP-internal
            # representations of VPN tunnel endpoints and have no PAN equivalent.
            # The actual tunnel interfaces are built from show_configuration VPN tunnels.
            if iname and ip and not re.match(r'^vpnt\d+$', iname, re.IGNORECASE):
                iface_data[iname] = {'ip': ip, 'mask_len': int(ml)}
    else:
        # No gateway_objects data — fall back to show_configuration.
        # Filter to only interfaces that appear as directly-connected routes.
        connected_ifaces = {r['interface'] for r in vs_data.get('routes', [])
                            if r.get('interface')}
        for cp_iface, info in cp_ifaces.items():
            if cp_iface in connected_ifaces:
                iface_data[cp_iface] = info

    iface_count = 0
    # Group interfaces by base (ae1, ethernet1/3, etc.)
    pan_to_units = {}  # {pan_base: [(vlan, ip, mask_len), ...]}
    for cp_iface, info in iface_data.items():
        pan_iface = _map_interface(cp_iface, iface_map)
        dot_pos = pan_iface.find('.')
        if dot_pos != -1:
            pan_base = pan_iface[:dot_pos]
            vlan_id  = pan_iface[dot_pos+1:]
        else:
            pan_base = pan_iface
            vlan_id  = None
        pan_to_units.setdefault(pan_base, []).append(
            (vlan_id, info.get('ip', ''), info.get('mask_len', 24))
        )

    # Write AE interfaces (only if any AE interfaces exist)
    ae_bases = [b for b in pan_to_units if b.startswith('ae')]
    if ae_bases:
        ae_el = _sub(ifaces_el, 'aggregate-ethernet')
        for pan_base in sorted(ae_bases):
            units = pan_to_units[pan_base]
            ae_entry = ET.SubElement(ae_el, 'entry')
            ae_entry.set('name', pan_base)
            layer3_el = _sub(ae_entry, 'layer3')
            units_el  = _sub(layer3_el, 'units')
            for vlan_id, ip, ml in sorted(units, key=lambda x: (x[0] or '')):
                if vlan_id:
                    unit_entry = ET.SubElement(units_el, 'entry')
                    unit_entry.set('name', f"{pan_base}.{vlan_id}")
                    _sub(unit_entry, 'tag', vlan_id)
                    if ip:
                        ipv4_el = _sub(unit_entry, 'ip')
                        _entry(ipv4_el, f"{ip}/{ml}")
                    iface_count += 1
                else:
                    # No VLAN tag — direct IP on the AE interface itself
                    if ip:
                        ipv4_el = _sub(layer3_el, 'ip')
                        _entry(ipv4_el, f"{ip}/{ml}")
                    iface_count += 1

    # Write ethernet interfaces (only if any ethernet interfaces exist)
    eth_bases = [b for b in pan_to_units if b.startswith('ethernet')]
    if eth_bases:
        eth_el = _sub(ifaces_el, 'ethernet')
        for pan_base in sorted(eth_bases):
            units = pan_to_units[pan_base]
            eth_entry = ET.SubElement(eth_el, 'entry')
            eth_entry.set('name', pan_base)
            layer3_el = _sub(eth_entry, 'layer3')
            units_el  = _sub(layer3_el, 'units')
            for vlan_id, ip, ml in sorted(units, key=lambda x: (x[0] or '')):
                if vlan_id:
                    unit_entry = ET.SubElement(units_el, 'entry')
                    unit_entry.set('name', f"{pan_base}.{vlan_id}")
                    _sub(unit_entry, 'tag', vlan_id)
                    if ip:
                        ipv4_el = _sub(unit_entry, 'ip')
                        _entry(ipv4_el, f"{ip}/{ml}")
                    iface_count += 1
                else:
                    if ip:
                        ipv4_el = _sub(layer3_el, 'ip')
                        _entry(ipv4_el, f"{ip}/{ml}")
                    iface_count += 1

    # Write other interfaces (not ae/ethernet — e.g. internet1, LAN, Mgmt)
    # These are written under <ethernet> as best-effort; user should remap via interface map.
    other_bases = [b for b in pan_to_units
                   if not b.startswith('ae') and not b.startswith('ethernet')]
    if other_bases:
        # Reuse existing eth_el if created above, otherwise create it now
        eth_other_el = ifaces_el.find('ethernet')
        if eth_other_el is None:
            eth_other_el = _sub(ifaces_el, 'ethernet')
        for pan_base in sorted(other_bases):
            units = pan_to_units[pan_base]
            other_entry = ET.SubElement(eth_other_el, 'entry')
            other_entry.set('name', pan_base)
            layer3_el = _sub(other_entry, 'layer3')
            units_el = None
            for vlan_id, ip, ml in sorted(units, key=lambda x: (x[0] or '')):
                if vlan_id:
                    if units_el is None:
                        units_el = _sub(layer3_el, 'units')
                    unit_entry = ET.SubElement(units_el, 'entry')
                    unit_entry.set('name', f"{pan_base}.{vlan_id}")
                    _sub(unit_entry, 'tag', vlan_id)
                    if ip:
                        ipv4_el = _sub(unit_entry, 'ip')
                        _entry(ipv4_el, f"{ip}/{ml}")
                else:
                    if ip:
                        ipv4_el = _sub(layer3_el, 'ip')
                        _entry(ipv4_el, f"{ip}/{ml}")
                iface_count += 1

    # ---- Tunnel interfaces for VPN ----
    vpn_tunnels = config.get('vpn_tunnels', [])
    tunnel_count = 0
    if vpn_tunnels:
        tunnel_el = _sub(ifaces_el, 'tunnel')
        tunnel_units_el = _sub(tunnel_el, 'units')
        for t in vpn_tunnels:
            tid  = t['id']
            tlocal = t['local']
            tentry = ET.SubElement(tunnel_units_el, 'entry')
            tentry.set('name', f"tunnel.{tid}")
            if tlocal:
                ipv4_el = _sub(tentry, 'ip')
                _entry(ipv4_el, f"{tlocal}/32")
            tunnel_count += 1

    # ---- Virtual Router ----
    vr_el   = _sub(network_el, 'virtual-router')
    vr_entry = ET.SubElement(vr_el, 'entry')
    vr_entry.set('name', vr_name)

    # Assign all interfaces (subinterfaces + tunnel interfaces) to this VR
    vr_iface_el = _sub(vr_entry, 'interface')
    for cp_iface in iface_data:
        pan_iface = _map_interface(cp_iface, iface_map)
        _member(vr_iface_el, pan_iface)
    for t in vpn_tunnels:
        _member(vr_iface_el, f"tunnel.{t['id']}")

    routing_el = _sub(vr_entry, 'routing-table')
    ip_el      = _sub(routing_el, 'ip')
    static_el  = _sub(ip_el, 'static-route')

    for route in routes:
        dest    = route.get('destination', '')
        nexthop = route.get('nexthop', '')
        cp_iface = route.get('interface', '')
        pan_iface = _map_interface(cp_iface, iface_map) if cp_iface else ''

        r_name = sanitize_name(f"route-{dest.replace('/', '-')}")
        r_entry = ET.SubElement(static_el, 'entry')
        r_entry.set('name', r_name)
        _sub(r_entry, 'destination', dest)
        nh_el = _sub(r_entry, 'nexthop')
        _sub(nh_el, 'ip-address', nexthop)
        if pan_iface:
            _sub(r_entry, 'interface', pan_iface)

    # ---- BGP ----
    bgp_cfg = config.get('bgp')
    if bgp_cfg and (bgp_cfg.get('local_as') or bgp_cfg.get('peers')):
        proto_el = _sub(vr_entry, 'protocol')
        bgp_el   = _sub(proto_el, 'bgp')
        _sub(bgp_el, 'enable', 'yes')
        if bgp_cfg.get('local_as'):
            _sub(bgp_el, 'local-as', str(bgp_cfg['local_as']))

        # Group peers by remote-AS — each remote-AS becomes a peer-group
        peer_groups = {}   # remote_as -> [peer_dict, ...]
        for p in bgp_cfg.get('peers', []):
            peer_groups.setdefault(p['remote_as'], []).append(p)

        if peer_groups:
            pg_container = _sub(bgp_el, 'peer-group')
            for remote_as, peers in sorted(peer_groups.items()):
                pg_entry = ET.SubElement(pg_container, 'entry')
                pg_name  = f"AS{remote_as}"
                pg_entry.set('name', pg_name)
                _sub(pg_entry, 'enable', 'yes')
                type_el = _sub(pg_entry, 'type')
                ebgp_el = _sub(type_el, 'ebgp')
                _sub(ebgp_el, 'remove-private-as', 'no')

                peer_container = _sub(pg_entry, 'peer')
                for p in peers:
                    peer_ip  = p['peer_ip']
                    pe_entry = ET.SubElement(peer_container, 'entry')
                    pe_name  = 'peer-' + peer_ip.replace('.', '-')
                    pe_entry.set('name', pe_name)
                    _sub(pe_entry, 'enable', 'yes')
                    addr_el = _sub(pe_entry, 'peer-address')
                    _sub(addr_el, 'ip', peer_ip)
                    conn_el = _sub(pe_entry, 'connection-options')
                    if p.get('keepalive') is not None:
                        _sub(conn_el, 'keep-alive-interval', str(p['keepalive']))
                    if p.get('holdtime') is not None:
                        _sub(conn_el, 'hold-time', str(p['holdtime']))
                    # Route-map comment — no direct PAN equivalent; note in description
                    notes = []
                    if p.get('import_map'):
                        notes.append(f"import:{p['import_map']}")
                    if p.get('export_map'):
                        notes.append(f"export:{p['export_map']}")
                    if notes:
                        _sub(pe_entry, 'description',
                             ('CP route-maps — configure manually: ' + ', '.join(notes))[:255])

        warnings.append(
            f"BGP local-AS {bgp_cfg.get('local_as')} configured with "
            f"{sum(len(v) for v in peer_groups.values())} peers. "
            "Route-maps (import/export) must be recreated manually as PAN-OS BGP filters."
        )

    # ---- IKE crypto profiles + IPSec crypto profiles + Gateways + Tunnels ----
    if vpn_tunnels:
        ike_el         = _sub(network_el, 'ike')
        ike_crypto_el  = _sub(ike_el, 'crypto-profiles')
        ike_profiles_el = _sub(ike_crypto_el, 'ike-crypto-profiles')
        gateway_el     = _sub(ike_el, 'gateway')

        ipsec_el           = _sub(network_el, 'tunnel')
        ipsec_crypto_el    = _sub(ipsec_el, 'crypto-profiles')
        ipsec_profiles_el  = _sub(ipsec_crypto_el, 'ipsec-crypto-profiles')
        ipsec_ipsec_el     = _sub(ipsec_el, 'ipsec')

        # Track crypto profiles already written (keyed by profile name)
        written_ike_profiles  = set()
        written_ipsec_profiles = set()

        for t in vpn_tunnels:
            tid       = t['id']
            peer_raw  = t['peer']
            peer      = sanitize_name(peer_raw)
            gw_name   = f"ike-gw-{peer}"[:31]
            ipsec_name = f"ipsec-{tid}-{peer}"[:31]

            ike_ver   = t.get('ike_version', 'ikev2')
            psk       = t.get('psk', '') or 'CHANGEME'
            p1        = t.get('p1', {})
            p2        = t.get('p2', {})

            # Real IKE peer IP (from VPN community); fall back to tunnel remote IP
            ike_peer_ip = t.get('ike_peer_ip') or t['remote']

            # ---- IKE crypto profile ----
            ike_profile_name = f"ike-{peer}"[:31]
            if ike_profile_name not in written_ike_profiles and p1:
                ike_prof_entry = ET.SubElement(ike_profiles_el, 'entry')
                ike_prof_entry.set('name', ike_profile_name)
                enc_el = _sub(ike_prof_entry, 'encryption')
                _member(enc_el, p1.get('encryption', 'aes-256-cbc'))
                hash_el = _sub(ike_prof_entry, 'hash')
                _member(hash_el, p1.get('hash', 'sha256'))
                dh_el = _sub(ike_prof_entry, 'dh-group')
                _member(dh_el, p1.get('dh_group', 'group14'))
                lt_el = _sub(ike_prof_entry, 'lifetime')
                _sub(lt_el, 'seconds', str(p1.get('lifetime_sec', 86400)))
                written_ike_profiles.add(ike_profile_name)

            # ---- IPSec crypto profile ----
            ipsec_profile_name = f"ipsec-{peer}"[:31]
            if ipsec_profile_name not in written_ipsec_profiles and p2:
                ipsec_prof_entry = ET.SubElement(ipsec_profiles_el, 'entry')
                ipsec_prof_entry.set('name', ipsec_profile_name)
                esp_el = _sub(ipsec_prof_entry, 'esp')
                enc_el = _sub(esp_el, 'encryption')
                _member(enc_el, p2.get('encryption', 'aes-256-cbc'))
                auth_el = _sub(esp_el, 'authentication')
                _member(auth_el, p2.get('hash', 'sha256'))
                lt_el = _sub(ipsec_prof_entry, 'lifetime')
                _sub(lt_el, 'seconds', str(p2.get('lifetime_sec', 3600)))
                pfs_group = p2.get('pfs_group')
                if pfs_group:
                    _sub(ipsec_prof_entry, 'dh-group', pfs_group)
                written_ipsec_profiles.add(ipsec_profile_name)

            # ---- IKE gateway ----
            gw_entry = ET.SubElement(gateway_el, 'entry')
            gw_entry.set('name', gw_name)

            auth_el = _sub(gw_entry, 'authentication')
            psk_el  = _sub(auth_el, 'pre-shared-key')
            _sub(psk_el, 'key', psk)

            proto_el = _sub(gw_entry, 'protocol')
            ver_el   = _sub(proto_el, ike_ver)   # <ikev1> or <ikev2>
            if p1:
                _sub(ver_el, 'ike-crypto-profile', ike_profile_name)
            if ike_ver == 'ikev1':
                _sub(ver_el, 'exchange-mode', 'main')

            local_el = _sub(gw_entry, 'local-address')
            _sub(local_el, 'ip', f"{t['local']}/32")

            peer_addr_el = _sub(gw_entry, 'peer-address')
            _sub(peer_addr_el, 'ip', ike_peer_ip)

            if psk == 'CHANGEME':
                warnings.append(
                    f"VPN tunnel {tid} (peer {peer_raw}): PSK not found in CP objects — "
                    f"set manually on IKE gateway '{gw_name}'."
                )

            # ---- IPSec tunnel ----
            ipsec_entry = ET.SubElement(ipsec_ipsec_el, 'entry')
            ipsec_entry.set('name', ipsec_name)
            _sub(ipsec_entry, 'tunnel-interface', f"tunnel.{tid}")
            ak_el = _sub(ipsec_entry, 'auto-key')
            gw_ref_el = _sub(ak_el, 'ike-gateway')
            _entry(gw_ref_el, gw_name)
            if p2:
                _sub(ak_el, 'ipsec-crypto-profile', ipsec_profile_name)

    # ---- Zones + vsys import (one zone per interface, named after the CP interface) ----
    # PAN-OS requires interfaces to be imported into a vsys before they can join a zone.
    vsys_el    = _sub(dev_entry, 'vsys')
    vsys_entry = _sub(vsys_el, 'entry')
    vsys_entry.set('name', 'vsys1')

    # import block — declares which interfaces belong to vsys1
    import_el  = _sub(vsys_entry, 'import')
    import_net = _sub(import_el, 'network')
    import_iface_el = _sub(import_net, 'interface')

    zone_el = _sub(vsys_entry, 'zone')

    for cp_iface in iface_data:
        pan_iface = _map_interface(cp_iface, iface_map)
        # Import interface into vsys1
        _member(import_iface_el, pan_iface)
        # Zone named after the CP interface (dots replaced with hyphens — PAN name constraint)
        zone_name = cp_iface.replace('.', '-')
        z_entry   = ET.SubElement(zone_el, 'entry')
        z_entry.set('name', zone_name)
        net_el    = _sub(z_entry, 'network')
        l3_el     = _sub(net_el, 'layer3')
        _member(l3_el, pan_iface)

    # Tunnel interfaces
    for t in vpn_tunnels:
        tname     = f"tunnel.{t['id']}"
        zone_name = f"vpn-{sanitize_name(t['peer'])}"
        _member(import_iface_el, tname)
        z_entry   = ET.SubElement(zone_el, 'entry')
        z_entry.set('name', zone_name)
        net_el    = _sub(z_entry, 'network')
        l3_el     = _sub(net_el, 'layer3')
        _member(l3_el, tname)

    return tmpl_entry, iface_count, tunnel_count


# ---------------------------------------------------------------------------
# Device Group builder
# ---------------------------------------------------------------------------

def _build_device_group(vs_data, iface_map, options, warnings):
    """
    Build a Panorama device-group ET.Element for the VS.

    Returns ET.Element <entry name="DG-...">
    along with counts for the report.
    """
    dg_name  = vs_data['dg_name']
    vs_name  = vs_data['vs_name']
    pkg      = vs_data.get('package', {})
    uid_map  = vs_data.get('uid_map', {})

    only_referenced = options.get('only_referenced_objects', False)

    dg_entry = ET.Element('entry')
    dg_entry.set('name', dg_name)

    addr_el    = _sub(dg_entry, 'address')
    addrgrp_el = _sub(dg_entry, 'address-group')
    svc_el     = _sub(dg_entry, 'service')
    svcgrp_el  = _sub(dg_entry, 'service-group')
    pre_rules_el = _sub(dg_entry, 'pre-rulebase')
    sec_pre_el   = _sub(pre_rules_el, 'security')
    sec_rules_el = _sub(sec_pre_el, 'rules')
    nat_pre_el   = _sub(pre_rules_el, 'nat')
    nat_rules_el = _sub(nat_pre_el, 'rules')

    objects       = pkg.get('objects', [])
    security_rules_raw = pkg.get('security_rules', [])
    nat_rules_raw      = pkg.get('nat_rules', [])

    used_obj_names  = set()
    used_rule_names = set()

    # Determine referenced UIDs (for "only referenced objects" mode)
    referenced_uids = set()
    if only_referenced:
        for rule in security_rules_raw:
            if rule.get('type') == 'access-rule':
                for lst in ('source', 'destination', 'service'):
                    for u in rule.get(lst, []):
                        referenced_uids.add(u)
        for rule in nat_rules_raw:
            if rule.get('type') == 'nat-rule':
                for field in ('original-source', 'original-destination', 'original-service',
                              'translated-source', 'translated-destination', 'translated-service'):
                    u = rule.get(field, '')
                    if u and u != 'original':
                        referenced_uids.add(u)
        # Expand groups
        def _expand_group_uids(uid):
            obj = uid_map.get(uid, {})
            if obj.get('type') in ('group', 'service-group'):
                for m in obj.get('members', []):
                    referenced_uids.add(m)
                    _expand_group_uids(m)
        for u in list(referenced_uids):
            _expand_group_uids(u)

    # Filter objects if needed
    if only_referenced and referenced_uids:
        filtered_objects = [o for o in objects if o.get('uid') in referenced_uids or
                            o.get('type') in ('RulebaseAction', 'CpmiAnyObject')]
    else:
        filtered_objects = objects

    # Build address objects
    addr_types = {'host', 'network', 'address-range', 'dns-domain', 'updatable-object'}
    addr_objects = [o for o in filtered_objects if o.get('type') in addr_types]

    uid_to_addr, addr_entries = _build_address_objects(
        addr_objects, uid_map, used_obj_names, warnings
    )
    for uid, pan_name, entry in addr_entries:
        addr_el.append(entry)

    # Build address groups
    grp_objects = [o for o in filtered_objects if o.get('type') == 'group']
    uid_to_grp, grp_entries = _build_address_groups(
        grp_objects, uid_to_addr, used_obj_names, warnings
    )
    for uid, pan_name, entry in grp_entries:
        addrgrp_el.append(entry)

    # Merge all address UIDs for resolver
    all_addr_uids = {**uid_to_addr, **uid_to_grp}

    # Build service objects
    svc_objects = [o for o in filtered_objects
                   if o.get('type') in ('service-tcp', 'service-udp',
                                        'service-icmp', 'service-other', 'service-group')]
    # Process individual services before groups so group member lookups succeed
    svc_objects = sorted(svc_objects, key=lambda o: 1 if o.get('type') == 'service-group' else 0)
    svc_uid_to_pan, svc_entries, grp_svc_uid, grp_svc_entries = _build_service_objects(
        svc_objects, all_addr_uids, used_obj_names, warnings
    )
    for uid, pan_name, entry in svc_entries:
        svc_el.append(entry)
    for uid, pan_name, entry in grp_svc_entries:
        svcgrp_el.append(entry)

    # Merge all UIDs for resolver
    all_uids = {**all_addr_uids, **svc_uid_to_pan, **grp_svc_uid}

    # Create resolver with full uid_map (needed for action lookup etc.)
    resolver = UIDResolver(uid_map, set(), vs_name, warnings)
    # Pre-seed cache with pre-computed service mappings so that ICMP/other UIDs
    # return their sentinels (__appid__:...) instead of the raw CP object name.
    for _uid, _pan_name in {**svc_uid_to_pan, **grp_svc_uid}.items():
        resolver._cache[_uid] = _pan_name
    # Pre-seed cache with address/group UIDs so deduplicated names (_2, _3 etc.)
    # are used correctly in NAT translated fields and security rules.
    for _uid, _pan_name in all_addr_uids.items():
        resolver._cache[_uid] = _pan_name

    # Build zone map from gateway_objects interface data for zone-based rule matching
    gw_objs = pkg.get('gateway_objects', [])
    iface_data_for_zones = {}
    if gw_objs:
        for gi in gw_objs[0].get('interfaces', []):
            iname = gi.get('interface-name', '')
            ip    = gi.get('ipv4-address', '')
            ml    = gi.get('ipv4-mask-length', 24)
            if iname and ip and not re.match(r'^vpnt\d+$', iname, re.IGNORECASE):
                iface_data_for_zones[iname] = {'ip': ip, 'mask_len': int(ml)}
    zone_map = _build_zone_map(iface_data_for_zones, iface_map)

    # Build security rules
    sec_entries, used_tags = _build_security_rules(security_rules_raw, resolver, used_rule_names,
                                                   warnings, zone_map=zone_map)
    for entry in sec_entries:
        sec_rules_el.append(entry)

    nat_entries = _build_nat_rules(nat_rules_raw, resolver, set(), warnings, zone_map=zone_map)
    for entry in nat_entries:
        nat_rules_el.append(entry)

    # Create tag objects for section tags (must exist in DG for Panorama to accept rule references)
    if used_tags:
        tag_container = _sub(dg_entry, 'tag')
        for tag_name in sorted(used_tags):
            tag_entry = ET.SubElement(tag_container, 'entry')
            tag_entry.set('name', tag_name)

    # Counts for report
    obj_counts = {
        'host':          len([o for o in addr_entries if uid_map.get(o[0], {}).get('type') == 'host']),
        'network':       len([o for o in addr_entries if uid_map.get(o[0], {}).get('type') == 'network']),
        'address-range': len([o for o in addr_entries if uid_map.get(o[0], {}).get('type') == 'address-range']),
        'dns-domain':    len([o for o in addr_entries if uid_map.get(o[0], {}).get('type') == 'dns-domain']),
        'address-group': len(grp_entries),
        'service':       len(svc_entries),
        'service-group': len(grp_svc_entries),
    }

    return dg_entry, obj_counts, len(sec_entries), len(nat_entries)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def build_panorama_xml(vs_data_list, existing_xml_str=None, interface_map=None, options=None):
    """
    Build a complete Panorama XML from a list of parsed VS data dicts.

    Args:
        vs_data_list:    list of dicts from cp_parser.parse_vs()
        existing_xml_str: string of existing Panorama XML to merge into (or None)
        interface_map:   {cp_prefix: pan_prefix} override (or None for defaults)
        options:         dict of conversion options:
                           'only_referenced_objects': bool (default False)
                           'prefix_object_names': bool (default False)

    Returns:
        (xml_string, report_list)
    """
    if interface_map is None:
        interface_map = dict(DEFAULT_INTERFACE_MAP)
    if options is None:
        options = {}

    report = []

    # ---- Parse or create root XML ----
    if existing_xml_str and existing_xml_str.strip():
        try:
            root = ET.fromstring(existing_xml_str.strip())
        except ET.ParseError as exc:
            log.warning("Could not parse existing XML: %s — starting fresh.", exc)
            root = None
    else:
        root = None

    if root is None:
        root = ET.Element('config')
        root.set('version', '10.2.0')
        ET.SubElement(root, 'mgt-config')
        devices_el = ET.SubElement(root, 'devices')
        dev_entry  = ET.SubElement(devices_el, 'entry')
        dev_entry.set('name', 'localhost.localdomain')
        ET.SubElement(dev_entry, 'device-group')
        ET.SubElement(dev_entry, 'template')

    # Find or create device-group and template nodes
    def _find_or_create(parent_path_parts, root_el):
        """Navigate/create a chain of elements by tag names."""
        current = root_el
        for part in parent_path_parts:
            found = current.find(part)
            if found is None:
                found = ET.SubElement(current, part)
            current = found
        return current

    # Locate <devices><entry><device-group>
    dg_container  = root.find('.//devices/entry/device-group')
    tmpl_container = root.find('.//devices/entry/template')

    if dg_container is None:
        dev_entry = root.find('.//devices/entry')
        if dev_entry is None:
            devices_el = _find_or_create(['devices'], root)
            dev_entry  = ET.SubElement(devices_el, 'entry')
            dev_entry.set('name', 'localhost.localdomain')
        dg_container   = ET.SubElement(dev_entry, 'device-group')
        tmpl_container = ET.SubElement(dev_entry, 'template')

    # Build set of existing DG / template names
    existing_dg_names   = {e.get('name', '') for e in dg_container.findall('entry')}
    existing_tmpl_names = {e.get('name', '') for e in tmpl_container.findall('entry')}

    for vs_data in vs_data_list:
        vs_name   = vs_data.get('vs_name', '?')
        dg_name   = vs_data.get('dg_name', f'DG-{vs_name}')
        tmpl_name = vs_data.get('tmpl_name', f'Tmpl-{vs_name}')

        vs_warnings = list(vs_data.get('warnings', []))
        vs_errors   = list(vs_data.get('errors', []))

        skipped = False
        if dg_name in existing_dg_names:
            vs_warnings.append(
                f"Device Group {dg_name!r} already exists in the target XML — skipped."
            )
            skipped = True

        obj_counts   = {}
        sec_rule_count = 0
        nat_rule_count = 0
        iface_count    = 0
        tunnel_count   = 0

        if not skipped:
            try:
                dg_entry, obj_counts, sec_rule_count, nat_rule_count = _build_device_group(
                    vs_data, interface_map, options, vs_warnings
                )
                dg_container.append(dg_entry)
                existing_dg_names.add(dg_name)
            except Exception as exc:
                vs_errors.append(f"Device group build failed: {exc}")
                log.exception("DG build error for %s", vs_name)

            try:
                tmpl_entry, iface_count, tunnel_count = _build_template(
                    vs_data, interface_map, vs_warnings
                )
                tmpl_container.append(tmpl_entry)
                existing_tmpl_names.add(tmpl_name)
            except Exception as exc:
                vs_errors.append(f"Template build failed: {exc}")
                log.exception("Template build error for %s", vs_name)

        report.append({
            'vs_name':           vs_name,
            'dg_name':           dg_name,
            'tmpl_name':         tmpl_name,
            'objects_converted': obj_counts,
            'rules_converted':   {'security': sec_rule_count, 'nat': nat_rule_count},
            'vpn_tunnels':       tunnel_count,
            'interfaces':        iface_count,
            'warnings':          vs_warnings,
            'errors':            vs_errors,
            'skipped':           skipped,
        })

    # ---- Serialize to pretty XML ----
    try:
        raw = ET.tostring(root, encoding='unicode')
        dom = minidom.parseString(raw)
        xml_str = dom.toprettyxml(indent='  ', encoding=None)
        # Remove minidom's auto-inserted XML declaration (we'll add our own)
        if xml_str.startswith('<?xml'):
            xml_str = xml_str[xml_str.index('?>') + 2:].lstrip()
        xml_str = '<?xml version="1.0" encoding="UTF-8"?>\n' + xml_str
    except Exception as exc:
        log.warning("Pretty-print failed: %s — returning raw XML.", exc)
        xml_str = ET.tostring(root, encoding='unicode', xml_declaration=True)

    return xml_str, report
