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

import copy
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
    'bond1':        'ae1',
    'bond2':        'ae2',
    'bond10':       'ae3',
    'ethernet4/1':  'ae1',
}

# VLAN 5 remapping: old inter-VS link (192.168.25.0/24) → new per-VS subinterface + IP
VLAN5_REMAP = {
    'VS-CPDNETS':   {'pan_iface': 'ae1.212', 'ip': '10.154.0.1',   'mask': 29},
    'VS-NAAS':      {'pan_iface': 'ae1.213', 'ip': '10.154.0.9',   'mask': 29},
    'VS-WEB1':      {'pan_iface': 'ae1.214', 'ip': '10.154.0.17',  'mask': 29},
    'VS-WEBX':      {'pan_iface': 'ae1.215', 'ip': '10.154.0.25',  'mask': 29},
    'VS-CLIENTES':  {'pan_iface': 'ae1.216', 'ip': '10.154.0.33',  'mask': 29},
    'VS-ENTIDADES': {'pan_iface': 'ae1.217', 'ip': '10.154.0.41',  'mask': 29},
    'VS-DMZ':       {'pan_iface': 'ae1.218', 'ip': '10.154.0.49',  'mask': 29},
    'VS-INTERNET':  {'pan_iface': 'ae1.219', 'ip': '10.154.0.57',  'mask': 29},
    'VS-MOBILE':    {'pan_iface': 'ae1.223', 'ip': '10.154.0.81',  'mask': 29},
    'VS-RBVPN':     {'pan_iface': 'ae1.221', 'ip': '10.154.0.73',  'mask': 29},
}
VLAN5_TAG = '5'

# Public (VLAN 520) vsys — single zone name used by all rules copied to DG-Public
PUBLIC_VLAN_TAG = '520'
PUBLIC_ZONE_NAME = f"Public_{PUBLIC_VLAN_TAG}"
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
        pan_name = f"ethernet{m.group(1)}/{int(m.group(2))}"  # strip leading zeros
        # Check if the converted PAN name has an override (e.g. ethernet4/1 → ae1)
        return iface_map.get(pan_name, pan_name)
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

def _zone_name_for_iface(cp_iface, vsys_label):
    """Derive zone name as {vsys_label}_{vlan_id}.

    If the CP interface has a dot (e.g. bond1.520), the VLAN ID is the part
    after the last dot.  For untagged interfaces the full sanitized interface
    name is used as suffix.
    """
    parts = cp_iface.split('.')
    if len(parts) >= 2:
        suffix = parts[-1]          # VLAN tag, e.g. "520"
    else:
        suffix = sanitize_name(cp_iface)
    return f"{vsys_label}_{suffix}"


def _build_zone_map(iface_data, iface_map, vsys_label=''):
    """
    Build a list of (zone_name, IPv4Network) from interface data.
    zone_name follows the pattern {vsys_label}_{vlan_id}.
    """
    zones = []
    for cp_iface, info in iface_data.items():
        ip  = info.get('ip', '')
        ml  = info.get('mask_len', 24)
        if not ip:
            continue
        try:
            net = ipaddress.IPv4Network(f"{ip}/{ml}", strict=False)
            zone_name = _zone_name_for_iface(cp_iface, vsys_label)
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
        # Final guard: PAN-OS rejects empty source arrays
        if len(src_el) == 0:
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
        # Final guard: PAN-OS rejects empty destination arrays
        if len(dst_el) == 0:
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


def _uid_matches_subnets(uid, uid_map, subnets, depth=0):
    """Check if a UID resolves to an IP that falls within any of the given subnets."""
    if depth > 5 or not uid or not subnets:
        return False
    obj = uid_map.get(uid)
    if obj is None:
        return False
    obj_type = obj.get('type', '')
    if obj_type == 'CpmiAnyObject' or obj.get('name', '').lower() == 'any':
        return False
    if obj_type == 'host':
        ip_str = obj.get('ipv4-address', '')
        if ip_str:
            try:
                addr = ipaddress.IPv4Address(ip_str)
                return any(addr in net for net in subnets)
            except ValueError:
                pass
    elif obj_type == 'network':
        ip_str = obj.get('subnet4', '')
        ml     = obj.get('mask-length4', 32)
        if ip_str:
            try:
                net = ipaddress.IPv4Network(f"{ip_str}/{ml}", strict=False)
                return any(net.overlaps(s) for s in subnets)
            except ValueError:
                pass
    elif obj_type == 'address-range':
        ip_first = obj.get('ipv4-address-first', '')
        if ip_first:
            try:
                addr = ipaddress.IPv4Address(ip_first)
                return any(addr in net for net in subnets)
            except ValueError:
                pass
    elif obj_type == 'group':
        for m_uid in obj.get('members', []):
            if _uid_matches_subnets(m_uid, uid_map, subnets, depth + 1):
                return True
    return False


def _nat_rule_involves_public(rule, uid_map, public_subnets):
    """Check if a NAT rule involves any public (VLAN 520) IP address."""
    if not public_subnets:
        return False
    for field in ('original-source', 'original-destination',
                  'translated-source', 'translated-destination'):
        uid = rule.get(field, '')
        if uid and uid != 'original':
            if _uid_matches_subnets(uid, uid_map, public_subnets):
                return True
    return False


def _sec_rule_involves_public(rule, uid_map, public_subnets):
    """Check if a security rule involves any public (VLAN 520) IP address."""
    if not public_subnets:
        return False
    for field in ('source', 'destination'):
        for uid in rule.get(field, []):
            if _uid_matches_subnets(uid, uid_map, public_subnets):
                return True
    return False


def _uids_match_subnets(uids, uid_map, subnets):
    """True if any UID in the list resolves to an IP within the given subnets."""
    if not subnets:
        return False
    for uid in uids:
        if _uid_matches_subnets(uid, uid_map, subnets):
            return True
    return False


def _rewrite_rule_zone(entry, tag, zone_name):
    """Replace <from>/<to> contents of a rule entry with a single <member>zone</member>."""
    el = entry.find(tag)
    if el is None:
        el = ET.SubElement(entry, tag)
    for child in list(el):
        el.remove(child)
    _member(el, zone_name)


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

        # Final guard: PAN-OS requires <service> in NAT rules
        if entry.find('service') is None:
            _sub(entry, 'service', 'any')

        # Description
        comment = item.get('comments', '')
        if comment:
            _sub(entry, 'description', comment[:1023])

        entries.append(entry)

    return entries


# ---------------------------------------------------------------------------
# Template builder (interfaces + routes + VPN)
# ---------------------------------------------------------------------------

def _build_template_vsys(vs_data, iface_map, network_el, vsys_container,
                         target_vsys, warnings):
    """
    Build network config into the shared template's <network> element,
    and create a vsys entry with zones + interface imports.

    Args:
        vs_data:         parsed VS data dict
        iface_map:       interface mapping dict
        network_el:      the shared <network> element inside the single template
        vsys_container:  the <vsys> container element inside the single template
        target_vsys:     name of the vsys to create (e.g. 'vsys2')
        warnings:        list to append warning strings to

    Returns:
        (iface_count, tunnel_count)
    """
    vr_name = vs_data['vr_name']
    config  = vs_data.get('config', {})
    routes  = vs_data.get('routes', [])

    # ---- Resolve interface data ----
    cp_ifaces = config.get('interfaces', {})
    gateway_ifaces = []
    pkg = vs_data.get('package', {})
    gw_objs = pkg.get('gateway_objects', [])
    if gw_objs:
        gw = gw_objs[0]
        gateway_ifaces = gw.get('interfaces', [])

    iface_data = {}  # {cp_iface_name: {ip, mask_len}}
    if gateway_ifaces:
        for gi in gateway_ifaces:
            iname = gi.get('interface-name', '')
            ip    = gi.get('ipv4-address', '')
            ml    = gi.get('ipv4-mask-length', 24)
            if iname and ip and not re.match(r'^vpnt\d+$', iname, re.IGNORECASE):
                iface_data[iname] = {'ip': ip, 'mask_len': int(ml)}
    else:
        connected_ifaces = {r['interface'] for r in vs_data.get('routes', [])
                            if r.get('interface')}
        for cp_iface, info in cp_ifaces.items():
            if cp_iface in connected_ifaces:
                iface_data[cp_iface] = info

    # ---- Split interfaces: VLAN 520 → "Public" vsys, rest → target_vsys ----
    public_iface_data = {}   # interfaces with VLAN 520
    main_iface_data   = {}   # everything else

    for cp_iface, info in iface_data.items():
        dot_pos = cp_iface.find('.')
        vlan_tag = cp_iface[dot_pos+1:] if dot_pos != -1 else None
        if vlan_tag == PUBLIC_VLAN_TAG:
            public_iface_data[cp_iface] = info
        else:
            main_iface_data[cp_iface] = info

    if public_iface_data:
        warnings.append(
            f"Interfaces with VLAN {PUBLIC_VLAN_TAG} detected: "
            f"{', '.join(sorted(public_iface_data.keys()))} — "
            f"these will be placed in vsys 'Public'."
        )

    # ---- VLAN 5 remapping: replace old inter-VS link with new per-VS subinterface ----
    # Only applies when the interface still carries the legacy 192.168.25.0/24 addressing.
    _VLAN5_OLD_NET = ipaddress.IPv4Network('192.168.25.0/24')
    vs_name = vs_data.get('vs_name', '')
    vlan5_remap_info = VLAN5_REMAP.get(vs_name)
    vlan5_cp_to_pan = {}   # {old_cp_iface: new_pan_iface} for route remapping

    if vlan5_remap_info:
        vlan5_entries = {}
        for k, v in main_iface_data.items():
            if '.' in k and k.split('.')[-1] == VLAN5_TAG:
                ip_str = v.get('ip', '')
                if ip_str:
                    try:
                        if ipaddress.IPv4Address(ip_str) in _VLAN5_OLD_NET:
                            vlan5_entries[k] = v
                    except ValueError:
                        pass
        if vlan5_entries:
            for old_cp_iface in vlan5_entries:
                del main_iface_data[old_cp_iface]
                vlan5_cp_to_pan[old_cp_iface] = vlan5_remap_info['pan_iface']
            # Add the remapped interface (PAN name as key so _map_interface passes it through)
            main_iface_data[vlan5_remap_info['pan_iface']] = {
                'ip':       vlan5_remap_info['ip'],
                'mask_len': vlan5_remap_info['mask'],
            }
            warnings.append(
                f"VLAN 5 interface(s) {', '.join(sorted(vlan5_entries.keys()))} "
                f"remapped → {vlan5_remap_info['pan_iface']} "
                f"({vlan5_remap_info['ip']}/{vlan5_remap_info['mask']})."
            )

    # ---- Write MAIN interfaces into shared <network><interface> ----
    # (VLAN 520 interfaces are written centrally by build_panorama_xml)
    ifaces_el = network_el.find('interface')
    if ifaces_el is None:
        ifaces_el = _sub(network_el, 'interface')

    iface_count = 0
    pan_to_units = {}  # {pan_base: [(vlan, ip, mask_len), ...]}
    for cp_iface, info in main_iface_data.items():
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

    # Write AE interfaces
    ae_bases = [b for b in pan_to_units if b.startswith('ae')]
    if ae_bases:
        ae_el = ifaces_el.find('aggregate-ethernet')
        if ae_el is None:
            ae_el = _sub(ifaces_el, 'aggregate-ethernet')
        for pan_base in sorted(ae_bases):
            units = pan_to_units[pan_base]
            # Find or create the base AE entry
            ae_entry = None
            for e in ae_el.findall('entry'):
                if e.get('name') == pan_base:
                    ae_entry = e
                    break
            if ae_entry is None:
                ae_entry = ET.SubElement(ae_el, 'entry')
                ae_entry.set('name', pan_base)
            layer3_el = ae_entry.find('layer3')
            if layer3_el is None:
                layer3_el = _sub(ae_entry, 'layer3')
            units_el = layer3_el.find('units')
            if units_el is None:
                units_el = _sub(layer3_el, 'units')
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
                        ipv4_el = layer3_el.find('ip')
                        if ipv4_el is None:
                            ipv4_el = _sub(layer3_el, 'ip')
                        _entry(ipv4_el, f"{ip}/{ml}")
                    iface_count += 1

    # Write ethernet interfaces
    eth_bases = [b for b in pan_to_units if b.startswith('ethernet')]
    if eth_bases:
        eth_el = ifaces_el.find('ethernet')
        if eth_el is None:
            eth_el = _sub(ifaces_el, 'ethernet')
        for pan_base in sorted(eth_bases):
            units = pan_to_units[pan_base]
            eth_entry = None
            for e in eth_el.findall('entry'):
                if e.get('name') == pan_base:
                    eth_entry = e
                    break
            if eth_entry is None:
                eth_entry = ET.SubElement(eth_el, 'entry')
                eth_entry.set('name', pan_base)
            layer3_el = eth_entry.find('layer3')
            if layer3_el is None:
                layer3_el = _sub(eth_entry, 'layer3')
            units_el = layer3_el.find('units')
            if units_el is None:
                units_el = _sub(layer3_el, 'units')
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
                        ipv4_el = layer3_el.find('ip')
                        if ipv4_el is None:
                            ipv4_el = _sub(layer3_el, 'ip')
                        _entry(ipv4_el, f"{ip}/{ml}")
                    iface_count += 1

    # Write other interfaces (not ae/ethernet)
    other_bases = [b for b in pan_to_units
                   if not b.startswith('ae') and not b.startswith('ethernet')]
    if other_bases:
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
        tunnel_el = ifaces_el.find('tunnel')
        if tunnel_el is None:
            tunnel_el = _sub(ifaces_el, 'tunnel')
        tunnel_units_el = tunnel_el.find('units')
        if tunnel_units_el is None:
            tunnel_units_el = _sub(tunnel_el, 'units')
        for t in vpn_tunnels:
            tid    = t['id']
            tlocal = t['local']
            tentry = ET.SubElement(tunnel_units_el, 'entry')
            tentry.set('name', f"tunnel.{tid}")
            if tlocal:
                ipv4_el = _sub(tentry, 'ip')
                _entry(ipv4_el, f"{tlocal}/32")
            tunnel_count += 1

    # ---- Partition routes: public vs main ----
    public_cp_ifaces_set = set(public_iface_data.keys())
    main_routes   = []
    public_routes = []
    for route in routes:
        if route.get('interface', '') in public_cp_ifaces_set:
            public_routes.append(route)
        else:
            main_routes.append(route)

    # ---- Main Virtual Router ----
    vr_el = network_el.find('virtual-router')
    if vr_el is None:
        vr_el = _sub(network_el, 'virtual-router')

    vr_entry = ET.SubElement(vr_el, 'entry')
    vr_entry.set('name', vr_name)

    vr_iface_el = _sub(vr_entry, 'interface')
    for cp_iface in main_iface_data:
        pan_iface = _map_interface(cp_iface, iface_map)
        _member(vr_iface_el, pan_iface)
    for t in vpn_tunnels:
        _member(vr_iface_el, f"tunnel.{t['id']}")

    routing_el = _sub(vr_entry, 'routing-table')
    ip_el      = _sub(routing_el, 'ip')
    static_el  = _sub(ip_el, 'static-route')

    # Pre-compute VLAN 5 gateway (last usable IP of the new /29 subnet)
    vlan5_gateway = None
    if vlan5_remap_info:
        _v5_net = ipaddress.IPv4Network(
            f"{vlan5_remap_info['ip']}/{vlan5_remap_info['mask']}", strict=False
        )
        vlan5_gateway = str(_v5_net.broadcast_address - 1)

    for route in main_routes:
        dest     = route.get('destination', '')
        nexthop  = route.get('nexthop', '')
        cp_iface = route.get('interface', '')
        # Use VLAN 5 remap if applicable, otherwise normal mapping
        if cp_iface and cp_iface in vlan5_cp_to_pan:
            pan_iface = vlan5_cp_to_pan[cp_iface]
            nexthop   = vlan5_gateway   # point to last usable IP of new subnet
        else:
            pan_iface = _map_interface(cp_iface, iface_map) if cp_iface else ''

        r_name  = sanitize_name(f"route-{dest.replace('/', '-')}")
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

        peer_groups = {}
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
        ike_el = network_el.find('ike')
        if ike_el is None:
            ike_el = _sub(network_el, 'ike')
        ike_crypto_el = ike_el.find('crypto-profiles')
        if ike_crypto_el is None:
            ike_crypto_el = _sub(ike_el, 'crypto-profiles')
        ike_profiles_el = ike_crypto_el.find('ike-crypto-profiles')
        if ike_profiles_el is None:
            ike_profiles_el = _sub(ike_crypto_el, 'ike-crypto-profiles')
        gateway_el = ike_el.find('gateway')
        if gateway_el is None:
            gateway_el = _sub(ike_el, 'gateway')

        ipsec_net_el = network_el.find('tunnel')
        if ipsec_net_el is None:
            ipsec_net_el = _sub(network_el, 'tunnel')
        ipsec_crypto_el = ipsec_net_el.find('crypto-profiles')
        if ipsec_crypto_el is None:
            ipsec_crypto_el = _sub(ipsec_net_el, 'crypto-profiles')
        ipsec_profiles_el = ipsec_crypto_el.find('ipsec-crypto-profiles')
        if ipsec_profiles_el is None:
            ipsec_profiles_el = _sub(ipsec_crypto_el, 'ipsec-crypto-profiles')
        ipsec_ipsec_el = ipsec_net_el.find('ipsec')
        if ipsec_ipsec_el is None:
            ipsec_ipsec_el = _sub(ipsec_net_el, 'ipsec')

        # Track already-written profiles (check existing entries)
        written_ike_profiles = {e.get('name') for e in ike_profiles_el.findall('entry')}
        written_ipsec_profiles = {e.get('name') for e in ipsec_profiles_el.findall('entry')}

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

            ike_peer_ip = t.get('ike_peer_ip') or t['remote']

            # IKE crypto profile
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

            # IPSec crypto profile
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

            # IKE gateway
            gw_entry = ET.SubElement(gateway_el, 'entry')
            gw_entry.set('name', gw_name)

            auth_el = _sub(gw_entry, 'authentication')
            psk_el  = _sub(auth_el, 'pre-shared-key')
            _sub(psk_el, 'key', psk)

            proto_el = _sub(gw_entry, 'protocol')
            ver_el   = _sub(proto_el, ike_ver)
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

            # IPSec tunnel
            ipsec_entry = ET.SubElement(ipsec_ipsec_el, 'entry')
            ipsec_entry.set('name', ipsec_name)
            _sub(ipsec_entry, 'tunnel-interface', f"tunnel.{tid}")
            ak_el = _sub(ipsec_entry, 'auto-key')
            gw_ref_el = _sub(ak_el, 'ike-gateway')
            _entry(gw_ref_el, gw_name)
            if p2:
                _sub(ak_el, 'ipsec-crypto-profile', ipsec_profile_name)

    # ---- Main vsys entry (zones + interface imports) ----
    vsys_entry = ET.SubElement(vsys_container, 'entry')
    vsys_entry.set('name', target_vsys)

    _sub(vsys_entry, 'display-name', vs_data.get('vs_name', target_vsys))

    import_el       = _sub(vsys_entry, 'import')
    import_net      = _sub(import_el, 'network')
    import_iface_el = _sub(import_net, 'interface')

    zone_el = _sub(vsys_entry, 'zone')

    # Derive a short label from the vsys display-name for zone naming
    vsys_label = sanitize_name(vs_data.get('vs_name', target_vsys))

    for cp_iface in main_iface_data:
        pan_iface = _map_interface(cp_iface, iface_map)
        _member(import_iface_el, pan_iface)
        zone_name = _zone_name_for_iface(cp_iface, vsys_label)
        z_entry   = ET.SubElement(zone_el, 'entry')
        z_entry.set('name', zone_name)
        net_el    = _sub(z_entry, 'network')
        l3_el     = _sub(net_el, 'layer3')
        _member(l3_el, pan_iface)

    # Tunnel interfaces into main vsys
    for t in vpn_tunnels:
        tname     = f"tunnel.{t['id']}"
        zone_name = f"{vsys_label}_vpn-{sanitize_name(t['peer'])}"
        _member(import_iface_el, tname)
        z_entry   = ET.SubElement(zone_el, 'entry')
        z_entry.set('name', zone_name)
        net_el    = _sub(z_entry, 'network')
        l3_el     = _sub(net_el, 'layer3')
        _member(l3_el, tname)

    # Import main virtual-router into main vsys
    import_vr_el = _sub(import_net, 'virtual-router')
    _member(import_vr_el, vr_name)

    # ---- Collect public data for centralized handling ----
    public_subnets = set()
    for info in public_iface_data.values():
        ip = info.get('ip', '')
        ml = info.get('mask_len', 24)
        if ip:
            try:
                public_subnets.add(ipaddress.IPv4Network(f"{ip}/{ml}", strict=False))
            except ValueError:
                pass

    return iface_count, tunnel_count, public_subnets, public_iface_data, public_routes


# ---------------------------------------------------------------------------
# Device Group builder
# ---------------------------------------------------------------------------

def _build_device_group(vs_data, iface_map, options, warnings, public_subnets=None):
    """
    Build a Panorama device-group ET.Element for the VS.

    NAT rules and security rules that involve public IPs (VLAN 520 subnets)
    are separated and returned for inclusion in the DG-Public device group.

    Returns:
        (dg_entry, obj_counts, sec_rule_count, nat_rule_count,
         public_nat_entries, public_sec_entries, public_obj_uids)
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

    # Build zone map from gateway_objects interface data for zone-based rule matching.
    # VLAN 520 interfaces are excluded — they've been moved to the Public vsys, so
    # zones like "VS-CLIENTES_520" don't exist in the main vsys.  UIDs that resolve
    # to 520 IPs will fall back to 'any' in the main DG rules.
    gw_objs = pkg.get('gateway_objects', [])
    iface_data_for_zones = {}
    if gw_objs:
        for gi in gw_objs[0].get('interfaces', []):
            iname = gi.get('interface-name', '')
            ip    = gi.get('ipv4-address', '')
            ml    = gi.get('ipv4-mask-length', 24)
            if not (iname and ip):
                continue
            if re.match(r'^vpnt\d+$', iname, re.IGNORECASE):
                continue
            # Skip VLAN 520 interfaces — they live in the Public vsys
            if '.' in iname and iname.split('.')[-1] == PUBLIC_VLAN_TAG:
                continue
            iface_data_for_zones[iname] = {'ip': ip, 'mask_len': int(ml)}
    # Apply VLAN 5 remapping to zone data so zone names match the template
    # Only when the interface carries the legacy 192.168.25.0/24 addressing
    _VLAN5_OLD_NET = ipaddress.IPv4Network('192.168.25.0/24')
    vlan5_remap_info = VLAN5_REMAP.get(vs_name)
    if vlan5_remap_info:
        vlan5_zone_entries = {}
        for k, v in iface_data_for_zones.items():
            if '.' in k and k.split('.')[-1] == VLAN5_TAG:
                ip_str = v.get('ip', '')
                if ip_str:
                    try:
                        if ipaddress.IPv4Address(ip_str) in _VLAN5_OLD_NET:
                            vlan5_zone_entries[k] = v
                    except ValueError:
                        pass
        for old_cp in vlan5_zone_entries:
            del iface_data_for_zones[old_cp]
        if vlan5_zone_entries:
            iface_data_for_zones[vlan5_remap_info['pan_iface']] = {
                'ip':       vlan5_remap_info['ip'],
                'mask_len': vlan5_remap_info['mask'],
            }

    vsys_label = sanitize_name(vs_name)
    zone_map = _build_zone_map(iface_data_for_zones, iface_map, vsys_label=vsys_label)

    # Build security rules (all go to main DG)
    sec_entries, used_tags = _build_security_rules(security_rules_raw, resolver, used_rule_names,
                                                   warnings, zone_map=zone_map)
    for entry in sec_entries:
        sec_rules_el.append(entry)

    # ---- Split security rules that involve public IPs → copy to DG-Public ----
    public_sec_raw = []
    if public_subnets:
        for item in security_rules_raw:
            if (item.get('type') == 'access-rule'
                    and item.get('enabled', True)
                    and _sec_rule_involves_public(item, uid_map, public_subnets)):
                public_sec_raw.append(item)

    public_sec_entries = []
    if public_sec_raw:
        public_sec_entries, _ = _build_security_rules(
            public_sec_raw, resolver, set(), warnings, zone_map=zone_map
        )
        # Rewrite zones: Public vsys only has the PUBLIC_ZONE_NAME zone, so each
        # rule's from/to must map to either PUBLIC_ZONE_NAME (if that side involves
        # 520 IPs) or 'any' (for the other side).
        for entry, raw in zip(public_sec_entries, public_sec_raw):
            src_is_pub = _uids_match_subnets(raw.get('source', []), uid_map, public_subnets)
            dst_is_pub = _uids_match_subnets(raw.get('destination', []), uid_map, public_subnets)
            _rewrite_rule_zone(entry, 'from', PUBLIC_ZONE_NAME if src_is_pub else 'any')
            _rewrite_rule_zone(entry, 'to',   PUBLIC_ZONE_NAME if dst_is_pub else 'any')
        warnings.append(
            f"{len(public_sec_entries)} security rule(s) involving VLAN 520 IPs "
            f"copied to DG-Public for inter-vsys traffic."
        )

    # ---- Split NAT rules: public (VLAN 520) vs main ----
    if public_subnets:
        main_nat_raw   = []
        public_nat_raw = []
        for item in nat_rules_raw:
            if item.get('type') == 'nat-rule' and _nat_rule_involves_public(item, uid_map, public_subnets):
                public_nat_raw.append(item)
            else:
                main_nat_raw.append(item)
    else:
        main_nat_raw   = nat_rules_raw
        public_nat_raw = []

    # Build main NAT rules
    nat_entries = _build_nat_rules(main_nat_raw, resolver, set(), warnings, zone_map=zone_map)
    for entry in nat_entries:
        nat_rules_el.append(entry)

    # Build public NAT rules (returned to caller for DG-Public)
    public_nat_entries = _build_nat_rules(public_nat_raw, resolver, set(), warnings, zone_map=zone_map)
    # Rewrite zones for Public vsys (same reason as security rules above)
    for entry, raw in zip(public_nat_entries, public_nat_raw):
        src_uid = raw.get('original-source', '')
        dst_uid = raw.get('original-destination', '')
        src_is_pub = bool(src_uid) and _uids_match_subnets([src_uid], uid_map, public_subnets)
        dst_is_pub = bool(dst_uid) and _uids_match_subnets([dst_uid], uid_map, public_subnets)
        _rewrite_rule_zone(entry, 'from', PUBLIC_ZONE_NAME if src_is_pub else 'any')
        _rewrite_rule_zone(entry, 'to',   PUBLIC_ZONE_NAME if dst_is_pub else 'any')

    # Collect UIDs referenced by public NAT + security rules (objects to copy to DG-Public)
    public_obj_uids = set()
    for item in public_nat_raw:
        if item.get('type') != 'nat-rule':
            continue
        for field in ('original-source', 'original-destination', 'original-service',
                      'translated-source', 'translated-destination', 'translated-service'):
            uid = item.get(field, '')
            if uid and uid != 'original' and not resolver.is_any(uid):
                public_obj_uids.add(uid)
    for item in public_sec_raw:
        for field in ('source', 'destination', 'service'):
            for uid in item.get(field, []):
                if uid and not resolver.is_any(uid):
                    public_obj_uids.add(uid)
    # Expand groups
    for u in list(public_obj_uids):
        obj = uid_map.get(u)
        if obj and obj.get('type') in ('group', 'service-group'):
            for m in obj.get('members', []):
                public_obj_uids.add(m)

    if public_nat_raw:
        warnings.append(
            f"{len(public_nat_raw)} NAT rule(s) involving VLAN 520 IPs moved to DG-Public."
        )

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

    return (dg_entry, obj_counts, len(sec_entries), len(nat_entries),
            public_nat_entries, public_sec_entries, public_obj_uids)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def build_panorama_xml(vs_data_list, existing_xml_str=None, interface_map=None,
                       template_name=None, options=None):
    """
    Build a complete Panorama XML from a list of parsed VS data dicts.

    Creates a SINGLE template with all network config (interfaces, VR, VPN)
    and one vsys per VS (named by the user via target_vsys).

    Args:
        vs_data_list:    list of dicts from cp_parser.parse_vs()
        existing_xml_str: string of existing Panorama XML to merge into (or None)
        interface_map:   {cp_prefix: pan_prefix} override (or None for defaults)
        template_name:   name for the single Panorama template (default 'Tmpl-Migration')
        options:         dict of conversion options:
                           'only_referenced_objects': bool (default False)
                           'prefix_object_names': bool (default False)

    Returns:
        (xml_string, report_list)
    """
    if interface_map is None:
        interface_map = dict(DEFAULT_INTERFACE_MAP)
    if template_name is None:
        template_name = 'Tmpl-Migration'
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

    # Build set of existing DG names
    existing_dg_names = {e.get('name', '') for e in dg_container.findall('entry')}

    # ---- Single template: find or create ----
    tmpl_entry = None
    for e in tmpl_container.findall('entry'):
        if e.get('name') == template_name:
            tmpl_entry = e
            break
    if tmpl_entry is None:
        tmpl_entry = ET.SubElement(tmpl_container, 'entry')
        tmpl_entry.set('name', template_name)

    # ---- Associate template with existing template-stack(s) ----
    # template-stack is a sibling of <template> and <device-group> under the
    # same <devices><entry name="localhost.localdomain">.
    # ElementTree has no parent navigation, so search for the right entry.
    template_stack_serials = []  # firewall serials to bind new DGs to
    for _de in root.findall('.//devices/entry'):
        ts_container_local = _de.find('template-stack')
        if ts_container_local is None or _de.find('template') is None:
            continue
        for ts_entry in ts_container_local.findall('entry'):
            ts_devices = ts_entry.find('devices')
            if ts_devices is None or len(ts_devices) == 0:
                continue
            for dev in ts_devices.findall('entry'):
                sn = dev.get('name', '')
                if sn and sn not in template_stack_serials:
                    template_stack_serials.append(sn)
            templates_el = ts_entry.find('templates')
            if templates_el is None:
                templates_el = _sub(ts_entry, 'templates')
            already = any(m.text == template_name
                          for m in templates_el.findall('member'))
            if not already:
                _member(templates_el, template_name)
                log.info("Template '%s' added to template-stack '%s'.",
                         template_name, ts_entry.get('name'))

    # Navigate to template internals
    config_el = tmpl_entry.find('config')
    if config_el is None:
        config_el = _sub(tmpl_entry, 'config')
    devices_tmpl_el = config_el.find('devices')
    if devices_tmpl_el is None:
        devices_tmpl_el = _sub(config_el, 'devices')
    dev_tmpl_entry = devices_tmpl_el.find('entry')
    if dev_tmpl_entry is None:
        dev_tmpl_entry = _sub(devices_tmpl_el, 'entry')
        dev_tmpl_entry.set('name', 'localhost.localdomain')

    network_el = dev_tmpl_entry.find('network')
    if network_el is None:
        network_el = _sub(dev_tmpl_entry, 'network')

    vsys_container = dev_tmpl_entry.find('vsys')
    if vsys_container is None:
        vsys_container = _sub(dev_tmpl_entry, 'vsys')

    # ---- Accumulators for the centralized "Public" vsys + DG ----
    # All VLAN 520 data from every VS is collected here, then written once at the end.
    all_public_iface_data = {}     # {cp_iface: {ip, mask_len}} — accumulated across VS
    all_public_routes     = []     # routes for the single VR-Public
    all_public_nat_entries  = []   # NAT rule XML elements for DG-Public
    all_public_sec_entries  = []   # Security rule XML elements for DG-Public
    all_public_obj_uids     = set()  # UIDs of objects to copy to DG-Public
    all_public_dg_entries   = []   # (dg_entry, public_obj_uids) per VS for object cloning

    dg_public = None
    dg_public_written_objs = set()
    new_dg_to_vsys = []  # list of (dg_entry, vsys_name) for final device binding

    def _ensure_dg_public():
        """Find or create DG-Public and its child containers."""
        nonlocal dg_public
        if dg_public is not None:
            return dg_public
        for e in dg_container.findall('entry'):
            if e.get('name') == 'DG-Public':
                dg_public = e
                return dg_public
        dg_public = ET.SubElement(dg_container, 'entry')
        dg_public.set('name', 'DG-Public')
        return dg_public

    # ---- Process each VS ----
    for vs_data in vs_data_list:
        vs_name      = vs_data.get('vs_name', '?')
        dg_name      = vs_data.get('dg_name', f'DG-{vs_name}')
        target_vsys  = vs_data.get('target_vsys', 'vsys1')

        vs_warnings = list(vs_data.get('warnings', []))
        vs_errors   = list(vs_data.get('errors', []))

        skipped = False
        if dg_name in existing_dg_names:
            vs_warnings.append(
                f"Device Group {dg_name!r} already exists in the target XML — skipped."
            )
            skipped = True

        obj_counts     = {}
        sec_rule_count = 0
        nat_rule_count = 0
        iface_count    = 0
        tunnel_count   = 0
        public_subnets = set()

        if not skipped:
            # Build network config first (to get public data for DG split)
            try:
                (iface_count, tunnel_count, public_subnets,
                 vs_public_iface_data, vs_public_routes) = _build_template_vsys(
                    vs_data, interface_map, network_el, vsys_container,
                    target_vsys, vs_warnings
                )
                # Accumulate public data for centralized handling
                all_public_iface_data.update(vs_public_iface_data)
                all_public_routes.extend(vs_public_routes)
            except Exception as exc:
                vs_errors.append(f"Template/vsys build failed: {exc}")
                log.exception("Template build error for %s", vs_name)
                public_subnets = set()

            # Build Device Group (policies + objects), splitting public rules
            try:
                (dg_entry, obj_counts, sec_rule_count, nat_rule_count,
                 public_nat_entries, public_sec_entries,
                 public_obj_uids) = _build_device_group(
                    vs_data, interface_map, options, vs_warnings,
                    public_subnets=public_subnets
                )
                dg_container.append(dg_entry)
                existing_dg_names.add(dg_name)
                new_dg_to_vsys.append((dg_entry, target_vsys))

                # Accumulate public rules and object refs
                all_public_nat_entries.extend(public_nat_entries)
                all_public_sec_entries.extend(public_sec_entries)
                if public_obj_uids:
                    all_public_dg_entries.append((dg_entry, public_obj_uids, vs_data.get('uid_map', {})))
                    all_public_obj_uids |= public_obj_uids

            except Exception as exc:
                vs_errors.append(f"Device group build failed: {exc}")
                log.exception("DG build error for %s", vs_name)

        report.append({
            'vs_name':           vs_name,
            'dg_name':           dg_name,
            'tmpl_name':         template_name,
            'target_vsys':       target_vsys,
            'objects_converted': obj_counts,
            'rules_converted':   {'security': sec_rule_count, 'nat': nat_rule_count},
            'vpn_tunnels':       tunnel_count,
            'interfaces':        iface_count,
            'warnings':          vs_warnings,
            'errors':            vs_errors,
            'skipped':           skipped,
            'public_nat_rules':  len(all_public_nat_entries),
            'public_sec_rules':  len(all_public_sec_entries),
        })

    # ---- Build centralized Public VR + vsys + DG (after all VS are processed) ----
    if all_public_iface_data:
        PUBLIC_VR_NAME = 'VR-Public'

        # --- Consolidate all 520 IPs onto a SINGLE subinterface ---
        # Pick the first 520 interface as the canonical one; all other IPs
        # are added as secondary addresses on that same subinterface.
        first_cp_iface = sorted(all_public_iface_data.keys())[0]
        canonical_pan_iface = _map_interface(first_cp_iface, interface_map)
        # Derive base + vlan from canonical (e.g. "ae1.520" → base="ae1", vlan="520")
        dot_pos = canonical_pan_iface.find('.')
        if dot_pos != -1:
            canonical_base = canonical_pan_iface[:dot_pos]
            canonical_vlan = canonical_pan_iface[dot_pos+1:]
        else:
            canonical_base = canonical_pan_iface
            canonical_vlan = '520'
        canonical_subif = f"{canonical_base}.{canonical_vlan}"

        # Collect all IPs from all 520 interfaces
        public_ips = []  # [(ip, mask_len), ...]
        for cp_iface in sorted(all_public_iface_data.keys()):
            info = all_public_iface_data[cp_iface]
            ip = info.get('ip', '')
            ml = info.get('mask_len', 24)
            if ip:
                public_ips.append((ip, ml))

        # --- Write the single consolidated 520 subinterface ---
        ifaces_el = network_el.find('interface')
        if ifaces_el is None:
            ifaces_el = _sub(network_el, 'interface')

        # Determine interface type (ae vs ethernet)
        if canonical_base.startswith('ae'):
            type_tag = 'aggregate-ethernet'
        else:
            type_tag = 'ethernet'

        type_el = ifaces_el.find(type_tag)
        if type_el is None:
            type_el = _sub(ifaces_el, type_tag)

        # Find or create the base interface entry
        base_entry = None
        for e in type_el.findall('entry'):
            if e.get('name') == canonical_base:
                base_entry = e
                break
        if base_entry is None:
            base_entry = ET.SubElement(type_el, 'entry')
            base_entry.set('name', canonical_base)

        layer3_el = base_entry.find('layer3')
        if layer3_el is None:
            layer3_el = _sub(base_entry, 'layer3')
        units_el = layer3_el.find('units')
        if units_el is None:
            units_el = _sub(layer3_el, 'units')

        # Create the single subinterface with ALL IPs
        unit_entry = ET.SubElement(units_el, 'entry')
        unit_entry.set('name', canonical_subif)
        _sub(unit_entry, 'tag', canonical_vlan)
        ipv4_el = _sub(unit_entry, 'ip')
        for ip, ml in public_ips:
            _entry(ipv4_el, f"{ip}/{ml}")

        # --- Public Virtual Router (single, one interface, all routes) ---
        vr_el = network_el.find('virtual-router')
        if vr_el is None:
            vr_el = _sub(network_el, 'virtual-router')

        public_vr_entry = ET.SubElement(vr_el, 'entry')
        public_vr_entry.set('name', PUBLIC_VR_NAME)

        pub_vr_iface_el = _sub(public_vr_entry, 'interface')
        _member(pub_vr_iface_el, canonical_subif)

        pub_routing_el = _sub(public_vr_entry, 'routing-table')
        pub_ip_el      = _sub(pub_routing_el, 'ip')
        pub_static_el  = _sub(pub_ip_el, 'static-route')

        used_route_names = set()
        for route in all_public_routes:
            dest    = route.get('destination', '')
            nexthop = route.get('nexthop', '')

            r_name = unique_name(
                sanitize_name(f"route-{dest.replace('/', '-')}"),
                used_route_names
            )
            r_entry = ET.SubElement(pub_static_el, 'entry')
            r_entry.set('name', r_name)
            _sub(r_entry, 'destination', dest)
            nh_el = _sub(r_entry, 'nexthop')
            _sub(nh_el, 'ip-address', nexthop)
            # All routes point to the single consolidated interface
            _sub(r_entry, 'interface', canonical_subif)

        # --- Public vsys (single interface, single zone) ---
        public_vsys = ET.SubElement(vsys_container, 'entry')
        public_vsys.set('name', 'Public')
        _sub(public_vsys, 'display-name', 'Public')

        pub_import_el    = _sub(public_vsys, 'import')
        pub_import_net   = _sub(pub_import_el, 'network')
        pub_import_iface = _sub(pub_import_net, 'interface')
        _member(pub_import_iface, canonical_subif)

        pub_zone_el = _sub(public_vsys, 'zone')
        pub_zone_name = f"Public_{canonical_vlan}"
        z_entry = ET.SubElement(pub_zone_el, 'entry')
        z_entry.set('name', pub_zone_name)
        net_el = _sub(z_entry, 'network')
        l3_el  = _sub(net_el, 'layer3')
        _member(l3_el, canonical_subif)

        pub_import_vr = _sub(pub_import_net, 'virtual-router')
        _member(pub_import_vr, PUBLIC_VR_NAME)

        # --- DG-Public (NAT + security rules + referenced objects) ---
        _ensure_dg_public()

        # Address / service / group containers
        pub_addr_el    = dg_public.find('address')
        if pub_addr_el is None:
            pub_addr_el = _sub(dg_public, 'address')
        pub_addrgrp_el = dg_public.find('address-group')
        if pub_addrgrp_el is None:
            pub_addrgrp_el = _sub(dg_public, 'address-group')
        pub_svc_el     = dg_public.find('service')
        if pub_svc_el is None:
            pub_svc_el = _sub(dg_public, 'service')
        pub_svcgrp_el  = dg_public.find('service-group')
        if pub_svcgrp_el is None:
            pub_svcgrp_el = _sub(dg_public, 'service-group')

        # Pre-rulebase with NAT + security
        pre_rules = dg_public.find('pre-rulebase')
        if pre_rules is None:
            pre_rules = _sub(dg_public, 'pre-rulebase')

        # NAT rules
        nat_pre = pre_rules.find('nat')
        if nat_pre is None:
            nat_pre = _sub(pre_rules, 'nat')
        nat_rules_pub_el = nat_pre.find('rules')
        if nat_rules_pub_el is None:
            nat_rules_pub_el = _sub(nat_pre, 'rules')
        for el in all_public_nat_entries:
            nat_rules_pub_el.append(el)

        # Security rules
        sec_pre = pre_rules.find('security')
        if sec_pre is None:
            sec_pre = _sub(pre_rules, 'security')
        sec_rules_pub_el = sec_pre.find('rules')
        if sec_rules_pub_el is None:
            sec_rules_pub_el = _sub(sec_pre, 'rules')
        for el in all_public_sec_entries:
            sec_rules_pub_el.append(el)

        # Copy referenced objects from each VS's DG to DG-Public
        obj_type_map = {
            'host': ('address', pub_addr_el),
            'network': ('address', pub_addr_el),
            'address-range': ('address', pub_addr_el),
            'dns-domain': ('address', pub_addr_el),
            'updatable-object': ('address', pub_addr_el),
            'group': ('address-group', pub_addrgrp_el),
            'service-tcp': ('service', pub_svc_el),
            'service-udp': ('service', pub_svc_el),
            'service-group': ('service-group', pub_svcgrp_el),
        }

        for dg_entry_ref, pub_uids, uid_map_ref in all_public_dg_entries:
            for obj_uid in pub_uids:
                obj = uid_map_ref.get(obj_uid)
                if obj is None:
                    continue
                obj_type = obj.get('type', '')
                mapping = obj_type_map.get(obj_type)
                if mapping is None:
                    continue
                source_tag, target_container = mapping
                source_container = dg_entry_ref.find(source_tag)
                if source_container is None:
                    continue
                base_name = sanitize_name(obj.get('name', ''))
                for entry_el in source_container.findall('entry'):
                    entry_name = entry_el.get('name', '')
                    if (entry_name == base_name
                            or entry_name.startswith(base_name + '_')):
                        if entry_name not in dg_public_written_objs:
                            target_container.append(copy.deepcopy(entry_el))
                            dg_public_written_objs.add(entry_name)
                        break

        log.info("DG-Public: %d NAT rules, %d security rules, %d objects",
                 len(all_public_nat_entries), len(all_public_sec_entries),
                 len(dg_public_written_objs))

        if dg_public is not None:
            new_dg_to_vsys.append((dg_public, 'Public'))

    # ---- Bind each new DG to the firewalls from the template-stack ----
    # Without this, Panorama cannot resolve zones for rules in the DG and
    # displays destination/source zone as "none" in the UI.
    if template_stack_serials and new_dg_to_vsys:
        for dg_entry, vsys_name in new_dg_to_vsys:
            devs_el = dg_entry.find('devices')
            if devs_el is None:
                devs_el = _sub(dg_entry, 'devices')
            existing_serials = {e.get('name') for e in devs_el.findall('entry')}
            for sn in template_stack_serials:
                if sn in existing_serials:
                    continue
                fw_entry = ET.SubElement(devs_el, 'entry')
                fw_entry.set('name', sn)
                vsys_container_el = _sub(fw_entry, 'vsys')
                vsys_bind = ET.SubElement(vsys_container_el, 'entry')
                vsys_bind.set('name', vsys_name)
            log.info("DG %r bound to %d firewall(s) with vsys %r.",
                     dg_entry.get('name'), len(template_stack_serials), vsys_name)

    # ---- NAT rules: expand <to> 'any' to all zones of the target vsys ----
    # PAN-OS rejects NAT rules with 'any' as destination zone — a specific zone
    # (or list of zones) must be declared.  For each new DG we know the bound
    # vsys, so we collect that vsys's zone names from the template and use them
    # as the NAT destination zone whenever the rule would otherwise say 'any'.
    vsys_zone_map = {}  # {vsys_name: [zone_names]}
    for vsys_e in vsys_container.findall('entry'):
        vn = vsys_e.get('name')
        zones = [z.get('name') for z in vsys_e.findall('zone/entry') if z.get('name')]
        if vn and zones:
            vsys_zone_map[vn] = zones

    for dg_entry, vsys_name in new_dg_to_vsys:
        zones = vsys_zone_map.get(vsys_name, [])
        if not zones:
            continue
        for nat_rule in dg_entry.findall('.//pre-rulebase/nat/rules/entry'):
            to_el = nat_rule.find('to')
            if to_el is None:
                to_el = _sub(nat_rule, 'to')
            members = [(m.text or '').strip() for m in to_el.findall('member')]
            has_specific = any(m and m.lower() != 'any' for m in members)
            if has_specific:
                # Strip any stray 'any' that snuck in alongside specific zones
                for m in list(to_el):
                    if (m.text or '').strip().lower() == 'any':
                        to_el.remove(m)
            else:
                # Only 'any' (or empty) — expand to all vsys zones
                for child in list(to_el):
                    to_el.remove(child)
                for z in zones:
                    _member(to_el, z)

    # ---- Final validation: ensure every NAT rule has <service> ----
    for dg_el in dg_container.findall('entry'):
        for nat_rule in dg_el.findall('.//pre-rulebase/nat/rules/entry'):
            if nat_rule.find('service') is None:
                _sub(nat_rule, 'service', 'any')
                log.warning("NAT rule %r in %s was missing <service> — added 'any'.",
                            nat_rule.get('name'), dg_el.get('name'))

    # ---- Final validation: ensure every NAT rule has valid <from>/<to> zones ----
    for dg_el in dg_container.findall('entry'):
        for nat_rule in dg_el.findall('.//pre-rulebase/nat/rules/entry'):
            for field in ('from', 'to'):
                el = nat_rule.find(field)
                if el is None:
                    el = _sub(nat_rule, field)
                for m in list(el):
                    txt = (m.text or '').strip()
                    if txt == '' or txt.lower() == 'none':
                        el.remove(m)
                if len(el) == 0:
                    _member(el, 'any')
                    log.warning("NAT rule %r in %s had invalid <%s> — replaced with 'any'.",
                                nat_rule.get('name'), dg_el.get('name'), field)

    # ---- Final validation: ensure every security rule has non-empty source/destination ----
    for dg_el in dg_container.findall('entry'):
        for sec_rule in dg_el.findall('.//pre-rulebase/security/rules/entry'):
            for field in ('source', 'destination'):
                el = sec_rule.find(field)
                if el is not None and len(el) == 0:
                    _member(el, 'any')
                    log.warning("Security rule %r in %s had empty <%s> — added 'any'.",
                                sec_rule.get('name'), dg_el.get('name'), field)

    # ---- Final validation: ensure every security rule has valid <from>/<to> zones ----
    for dg_el in dg_container.findall('entry'):
        for sec_rule in dg_el.findall('.//pre-rulebase/security/rules/entry'):
            for field in ('from', 'to'):
                el = sec_rule.find(field)
                if el is None:
                    el = _sub(sec_rule, field)
                for m in list(el):
                    txt = (m.text or '').strip()
                    if txt == '' or txt.lower() == 'none':
                        el.remove(m)
                if len(el) == 0:
                    _member(el, 'any')
                    log.warning("Security rule %r in %s had invalid <%s> — replaced with 'any'.",
                                sec_rule.get('name'), dg_el.get('name'), field)

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
