#!/usr/bin/env python3
"""
DomainRadar Async Scanner — WSL2 Edition
==========================================
Quét 2M+ domains bằng asyncio, tối ưu cho WSL2 (5.7GB RAM, 12 CPU, WiFi 56Mbps).
Output format giống hệt scanned_benign.json gốc.

Cách dùng:
    python3 scanner_async.py --input labeled_domains.csv --output scanned_output --workers 300
    python3 scanner_async.py --input labeled_domains.csv --output scanned_output --resume
"""

import argparse
import asyncio
import csv
import json
import os
import re
import signal
import socket
import ssl
import sys
import time
import traceback
from collections import defaultdict
from datetime import datetime, timezone
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Try uvloop for better performance
try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    USING_UVLOOP = True
except ImportError:
    USING_UVLOOP = False

import dns.resolver
import dns.name
import dns.rdatatype
import aiohttp

import OpenSSL.SSL
from OpenSSL.crypto import X509

# ============================================================
# CẤU HÌNH
# ============================================================
DNS_SERVERS = ['8.8.8.8', '1.1.1.1', '8.8.4.4', '1.0.0.1', '9.9.9.9']
DNS_TIMEOUT = 5             # Tăng từ 3 → 5s để giảm DNS null
TLS_TIMEOUT = 6             # Tăng từ 4 → 6s để giảm TLS null
RDAP_TIMEOUT = 8            # Tăng từ 5 → 8s để giảm RDAP null
DOMAIN_TIMEOUT = 60         # Tăng từ 45 → 60s (đủ cho retry)
MAX_WORKERS = 300           # Concurrent domains
CHECKPOINT_EVERY = 5000     # Save checkpoint mỗi N domains
PROGRESS_EVERY = 50         # In progress mỗi N domains

# Retry settings
DNS_RETRY = 2               # Số lần retry DNS khi fail
TLS_RETRY = 2               # Số lần retry TLS khi fail
RDAP_RETRY = 2              # Số lần retry RDAP khi fail

# Semaphore limits (tránh quá tải mạng/RAM)
SEM_DNS = 500
SEM_TLS = 200
SEM_RDAP = 150              # Tăng từ 100 → 150
SEM_IP_RDAP = 100           # Tăng từ 80 → 100

# DNS record types cần quét
DNS_RECORD_TYPES = ('A', 'AAAA', 'SOA', 'CNAME', 'MX', 'NS', 'TXT')

# RDAP Bootstrap URLs
RDAP_DOMAIN_BOOTSTRAP = {
    'com': 'https://rdap.verisign.com/com/v1',
    'net': 'https://rdap.verisign.com/net/v1',
    'org': 'https://rdap.org.afilias.info/rdap/org/v1',
    'info': 'https://rdap.afilias.info/rdap/info/v1',
    'io': 'https://rdap.nic.io',
    'me': 'https://rdap.nic.me',
    'co': 'https://rdap.nic.co',
    'us': 'https://rdap.nic.us',
    'uk': 'https://rdap.nominet.uk/uk',
    'de': 'https://rdap.denic.de',
    'eu': 'https://rdap.eu',
    'ru': 'https://rdap.tcinet.ru',
    'jp': 'https://rdap.jprs.jp/rdap',
    'cn': 'https://rdap.cnnic.cn/rdap',
    'app': 'https://rdap.nic.google',
    'dev': 'https://rdap.nic.google',
    'xyz': 'https://rdap.nic.xyz',
    'top': 'https://rdap.nic.top',
    'online': 'https://rdap.donuts.co/rdap',
    'site': 'https://rdap.donuts.co/rdap',
    'store': 'https://rdap.donuts.co/rdap',
    'club': 'https://rdap.nic.club',
    'vip': 'https://rdap.nic.vip',
    'shop': 'https://rdap.nic.shop',
    'buzz': 'https://rdap.nic.buzz',
    'casino': 'https://rdap.donuts.co/rdap',
    'click': 'https://rdap.donuts.co/rdap',
    'biz': 'https://rdap.nic.biz',
    'nl': 'https://rdap.sidn.nl',
    'fr': 'https://rdap.nic.fr',
    'it': 'https://rdap.nic.it',
    'br': 'https://rdap.registro.br',
    'au': 'https://rdap.auda.org.au',
    'ca': 'https://rdap.ca.fury.ca/rdap',
    'in': 'https://rdap.registry.in',
    'kr': 'https://rdap.kisa.or.kr/rdap',
    'tw': 'https://rdap.twnic.tw',
    'za': 'https://rdap.nic.za',
    'pl': 'https://rdap.dns.pl',
    'se': 'https://rdap.iis.se',
    'cz': 'https://rdap.nic.cz',
    'at': 'https://rdap.nic.at',
    'ch': 'https://rdap.nic.ch',
    'pe': 'https://rdap.nic.pe',
    'ir': 'https://rdap.nic.ir',
    'ua': 'https://rdap.hostmaster.ua',
}

# RDAP IP bootstrap
RDAP_IP_URLS = [
    'https://rdap.arin.net/registry',
    'https://rdap.ripe.net',
    'https://rdap.apnic.net',
    'https://rdap.lacnic.net/rdap',
    'https://rdap.afrinic.net/rdap',
]

HOSTNAME_REGEX = r"(?:[a-z0-9](?:[a-z0-9-_]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]"


# ============================================================
# GLOBAL STATE
# ============================================================
class ScanState:
    """Shared state cho scanner"""
    def __init__(self):
        self.completed = 0
        self.failed = 0
        self.total = 0
        self.start_time = 0
        self.interrupted = False
        self.dns_sem = None
        self.tls_sem = None
        self.rdap_sem = None
        self.ip_rdap_sem = None
        self.aio_session = None
        self.rdap_ip_cache = {}  # Cache IP RDAP by prefix
        self.rdap_bootstrap_done = False
        # Stats
        self.stats_dns_ok = 0
        self.stats_tls_ok = 0
        self.stats_rdap_ok = 0

state = ScanState()


# ============================================================
# DNS RESOLVER (sync, run in executor)
# ============================================================
# Global DNS cache — chia sẻ giữa các thread
_dns_cache = dns.resolver.LRUCache(10000)

def _resolve_dns_sync(domain_name):
    """Resolve DNS records — chạy trong thread executor, có retry"""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = DNS_SERVERS
    resolver.lifetime = DNS_TIMEOUT
    resolver.timeout = DNS_TIMEOUT
    resolver.cache = _dns_cache  # Dùng cache chung

    domain = dns.name.from_text(domain_name)

    result = {
        'dnssec': {}, 'remarks': {}, 'sources': {}, 'ttls': {},
        'SOA': None, 'zone_SOA': None, 'NS': None, 'A': None,
        'AAAA': None, 'CNAME': None, 'MX': None, 'TXT': None
    }
    ips = []

    # Zone SOA
    try:
        answer = resolver.resolve(domain, 'SOA')
        from dns.rdtypes.ANY.SOA import SOA as SOAType
        soa_recs = [a for a in answer.rrset if isinstance(a, SOAType)]
        if soa_recs:
            soa = soa_recs[0]
            result['zone_SOA'] = {
                'primary_ns': soa.mname.to_text(True),
                'resp_mailbox_dname': soa.rname.to_text(True),
                'serial': soa.serial, 'refresh': soa.refresh,
                'retry': soa.retry, 'expire': soa.expire,
                'min_ttl': soa.minimum
            }
    except Exception:
        pass

    # Each record type
    for rtype in DNS_RECORD_TYPES:
        result['dnssec'][rtype] = 3   # default
        result['sources'][rtype] = 2  # CANNOT_RESOLVE
        result['ttls'][rtype] = 0
        try:
            answer = resolver.resolve(domain, rtype)
            result['sources'][rtype] = 0  # AUTHORITATIVE-ish
            result['ttls'][rtype] = answer.rrset.ttl

            if rtype == 'A':
                result['A'] = [r.address for r in answer]
                for r in answer:
                    ips.append({'ip': r.address, 'from': 'A'})
            elif rtype == 'AAAA':
                result['AAAA'] = [r.address for r in answer]
                for r in answer:
                    ips.append({'ip': r.address, 'from': 'AAAA'})
            elif rtype == 'CNAME':
                target = answer[0].target.to_text(True)
                result['CNAME'] = target
            elif rtype == 'MX':
                mx_dict = {}
                for r in answer:
                    exchange = r.exchange.to_text(True)
                    mx_dict[exchange] = {'priority': r.preference, 'related_ips': []}
                    # Resolve MX IPs
                    try:
                        mx_a = resolver.resolve(exchange, 'A')
                        mx_dict[exchange]['related_ips'] = [
                            {'ttl': mx_a.rrset.ttl, 'value': rr.address} for rr in mx_a
                        ]
                    except Exception:
                        pass
                result['MX'] = mx_dict if mx_dict else None
            elif rtype == 'NS':
                ns_dict = {}
                for r in answer:
                    ns_name = r.target.to_text(True)
                    ns_dict[ns_name] = {'related_ips': []}
                    # Resolve NS IPs
                    try:
                        ns_a = resolver.resolve(ns_name, 'A')
                        for rr in ns_a:
                            ns_dict[ns_name]['related_ips'].append(
                                {'ttl': ns_a.rrset.ttl, 'value': rr.address}
                            )
                    except Exception:
                        pass
                    try:
                        ns_aaaa = resolver.resolve(ns_name, 'AAAA')
                        for rr in ns_aaaa:
                            ns_dict[ns_name]['related_ips'].append(
                                {'ttl': ns_aaaa.rrset.ttl, 'value': rr.address}
                            )
                    except Exception:
                        pass
                result['NS'] = ns_dict if ns_dict else None
            elif rtype == 'TXT':
                result['TXT'] = []
                for r in answer:
                    for s in r.strings:
                        try:
                            text = s.decode()
                            result['TXT'].append(text)
                            tl = text.lower()
                            if 'v=spf1' in tl:
                                result['remarks']['has_spf'] = True
                            if 'v=dkim1' in tl:
                                result['remarks']['has_dkim'] = True
                            if 'v=dmarc1' in tl:
                                result['remarks']['has_dmarc'] = True
                        except Exception:
                            pass
                if not result['TXT']:
                    result['TXT'] = None
            elif rtype == 'SOA':
                from dns.rdtypes.ANY.SOA import SOA as SOAType
                soa_recs = [a for a in answer if isinstance(a, SOAType)]
                if soa_recs:
                    s = soa_recs[0]
                    result['SOA'] = {
                        'primary_ns': s.mname.to_text(True),
                        'resp_mailbox_dname': s.rname.to_text(True),
                        'serial': s.serial, 'refresh': s.refresh,
                        'retry': s.retry, 'expire': s.expire,
                        'min_ttl': s.minimum
                    }
                    result['sources']['SOA'] = 0
        except dns.resolver.NXDOMAIN:
            result['sources'][rtype] = 2
        except dns.resolver.NoAnswer:
            result['sources'][rtype] = 2
        except dns.resolver.NoNameservers:
            result['sources'][rtype] = 2
        except Exception:
            pass

    # DNSKEY check
    result['remarks']['has_dnskey'] = False
    result['remarks']['zone_dnskey_selfsign_ok'] = False
    try:
        answer = resolver.resolve(domain, 'DNSKEY')
        if answer.rrset and len(answer.rrset) > 0:
            result['remarks']['has_dnskey'] = True
    except Exception:
        pass

    # Zone name
    parts = domain_name.split('.')
    if len(parts) > 2:
        result['remarks']['zone'] = '.'.join(parts[-2:])
    else:
        result['remarks']['zone'] = domain_name

    return result, ips


# ============================================================
# TLS RESOLVER (sync, run in executor) — CÓ RETRY
# ============================================================
def _resolve_tls_sync(domain_name):
    """Resolve TLS certificate — chạy trong thread executor, có retry"""
    for attempt in range(TLS_RETRY):
        sock_raw = None
        try:
            sock_raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_raw.settimeout(TLS_TIMEOUT)

            ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLS_CLIENT_METHOD)
            ctx.set_timeout(int(TLS_TIMEOUT))

            conn = OpenSSL.SSL.Connection(context=ctx, socket=sock_raw)
            conn.set_connect_state()
            conn.set_tlsext_host_name(domain_name.encode())

            try:
                conn.connect((domain_name, 443))
            except OSError:
                if attempt < TLS_RETRY - 1:
                    time.sleep(0.5)
                    continue
                return None

            try:
                conn.do_handshake()
            except OpenSSL.SSL.WantReadError:
                time.sleep(0.5)
                try:
                    conn.do_handshake()
                except Exception:
                    if attempt < TLS_RETRY - 1:
                        continue
                    return None
            except Exception:
                if attempt < TLS_RETRY - 1:
                    time.sleep(0.3)
                    continue
                return None

            result = {
                'cipher': conn.get_cipher_name(),
                'protocol': conn.get_protocol_version_name(),
                'count': 0,
                'certificates': []
            }

            chain = None
            try:
                chain = conn.get_verified_chain()
            except Exception:
                try:
                    chain = conn.get_peer_cert_chain()
                except Exception:
                    pass

            if chain:
                result['count'] = len(chain)
                for i, cert in enumerate(chain):
                    result['certificates'].append(
                        _parse_cert(cert, i == len(chain) - 1)
                    )

            return result

        except Exception:
            if attempt < TLS_RETRY - 1:
                time.sleep(0.3)
                continue
            return None
        finally:
            if sock_raw:
                try:
                    sock_raw.close()
                except Exception:
                    pass
    return None


def _parse_cert(cert, is_root=False):
    """Parse X509 certificate thành dict"""
    valid_from_raw = cert.get_notBefore()
    valid_to_raw = cert.get_notAfter()
    valid_from = valid_to = validity_len = None

    if valid_from_raw and valid_to_raw:
        try:
            vf = datetime.strptime(valid_from_raw.decode()[:-1], "%Y%m%d%H%M%S")
            vt = datetime.strptime(valid_to_raw.decode()[:-1], "%Y%m%d%H%M%S")
            valid_from = vf.strftime("%Y-%m-%d %H:%M:%S")
            valid_to = vt.strftime("%Y-%m-%d %H:%M:%S")
            validity_len = int((vt - vf).total_seconds())
        except Exception:
            pass

    issuer_str = str(cert.get_issuer())
    attrs = issuer_str.split('/')
    cn = org = country = None
    for attr in attrs:
        parts = attr.split('=', 1)
        if len(parts) == 2:
            if parts[0] == 'CN':
                cn = parts[1]
            elif parts[0] == 'O':
                org = parts[1]
            elif parts[0] == 'C':
                country = parts[1]

    extensions = []
    for i in range(cert.get_extension_count()):
        ext = cert.get_extension(i)
        try:
            val = str(ext)
        except Exception:
            val = None
        extensions.append({
            'critical': ext.get_critical(),
            'name': ext.get_short_name().decode(),
            'value': val
        })

    return {
        'common_name': cn,
        'organization': org,
        'country': country,
        'validity_start': valid_from,
        'validity_end': valid_to,
        'valid_len': validity_len,
        'extensions': extensions,
        'extension_count': len(extensions),
        'is_root': is_root
    }


# ============================================================
# RDAP RESOLVER (async via aiohttp)
# ============================================================
async def _resolve_rdap_domain(domain_name):
    """RDAP domain lookup via HTTP — CÓ RETRY + FALLBACK"""
    tld = domain_name.rsplit('.', 1)[-1].lower() if '.' in domain_name else ''
    base_url = RDAP_DOMAIN_BOOTSTRAP.get(tld)

    # Danh sách URL thử theo thứ tự
    urls_to_try = []
    if base_url:
        urls_to_try.append(f"{base_url}/domain/{domain_name}")
    urls_to_try.append(f"https://rdap.org/domain/{domain_name}")  # Fallback IANA

    for attempt in range(RDAP_RETRY):
        for url in urls_to_try:
            try:
                async with state.aio_session.get(
                    url, timeout=aiohttp.ClientTimeout(total=RDAP_TIMEOUT),
                    allow_redirects=True, ssl=False
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        return _parse_rdap_domain(data, domain_name)
                    elif resp.status == 429:  # Rate limited
                        await asyncio.sleep(1.0 * (attempt + 1))
                        break  # Retry outer loop
                    # 404/other → try next URL
            except asyncio.TimeoutError:
                continue
            except Exception:
                continue
    return None


def _parse_rdap_domain(data, domain_name):
    """Parse RDAP JSON response thành format giống output gốc"""
    if not data:
        return None

    result = {
        'handle': data.get('handle', ''),
        'parent_handle': '',
        'name': domain_name,
        'whois_server': '',
        'type': 'domain',
        'terms_of_service_url': '',
        'copyright_notice': '',
        'description': [],
        'last_changed_date': None,
        'registration_date': None,
        'expiration_date': None,
        'url': '',
        'rir': '',
        'entities': {},
        'unicode_name': data.get('unicodeName', ''),
        'nameservers': [],
        'status': data.get('status', []),
        'dnssec': False
    }

    # Links
    for link in data.get('links', []):
        if link.get('rel') == 'self':
            result['url'] = link.get('href', '')
        elif link.get('rel') == 'related' and 'terms' in link.get('href', '').lower():
            result['terms_of_service_url'] = link.get('href', '')

    # Events (dates)
    for event in data.get('events', []):
        action = event.get('eventAction', '')
        date_str = event.get('eventDate', '')
        if action == 'registration':
            result['registration_date'] = date_str
        elif action == 'expiration':
            result['expiration_date'] = date_str
        elif action in ('last changed', 'last update'):
            result['last_changed_date'] = date_str

    # Nameservers
    for ns in data.get('nameservers', []):
        ns_name = ns.get('ldhName', '')
        if ns_name:
            result['nameservers'].append(ns_name.lower())

    # DNSSEC
    sec_dns = data.get('secureDNS', {})
    if sec_dns:
        result['dnssec'] = sec_dns.get('delegationSigned', False)

    # Entities
    for entity in data.get('entities', []):
        roles = entity.get('roles', [])
        entity_data = _parse_rdap_entity(entity)
        for role in roles:
            role_key = role.lower()
            if role_key not in result['entities']:
                result['entities'][role_key] = []
            result['entities'][role_key].append(entity_data)

    # Notices
    for notice in data.get('notices', []):
        title = notice.get('title', '').lower()
        if 'terms' in title:
            for link in notice.get('links', []):
                if not result['terms_of_service_url']:
                    result['terms_of_service_url'] = link.get('href', '')
        if 'copyright' in title:
            desc = notice.get('description', [])
            if desc:
                result['copyright_notice'] = ' '.join(desc)

    return result


def _parse_rdap_entity(entity):
    """Parse entity from RDAP response"""
    result = {
        'type': 'entity',
        'whois_server': '',
        'name': '',
        'address': {
            'po_box': '', 'ext_address': '', 'street_address': '',
            'locality': '', 'region': '', 'postal_code': '', 'country': ''
        },
    }

    # Handle
    if 'handle' in entity:
        result['handle'] = entity['handle']
    if 'port43' in entity:
        result['whois_server'] = entity['port43']

    # vCard
    vcard = entity.get('vcardArray', [])
    if vcard and len(vcard) > 1:
        for item in vcard[1]:
            if not isinstance(item, list) or len(item) < 4:
                continue
            prop_type = item[0]
            value = item[3]
            if prop_type == 'fn':
                result['name'] = value
            elif prop_type == 'email':
                result['email'] = value
            elif prop_type == 'tel':
                tel_val = value
                if isinstance(value, list):
                    tel_val = value[0] if value else ''
                result['tel'] = tel_val
            elif prop_type == 'adr':
                if isinstance(value, list) and len(value) >= 7:
                    result['address'] = {
                        'po_box': value[0] or '',
                        'ext_address': value[1] or '',
                        'street_address': value[2] or '',
                        'locality': value[3] or '',
                        'region': value[4] or '',
                        'postal_code': value[5] or '',
                        'country': value[6] or ''
                    }

    # Links
    for link in entity.get('links', []):
        if link.get('rel') == 'self':
            result['url'] = link.get('href', '')
            if 'arin' in link.get('href', ''):
                result['rir'] = 'arin'
            elif 'ripe' in link.get('href', ''):
                result['rir'] = 'ripe'
            elif 'apnic' in link.get('href', ''):
                result['rir'] = 'apnic'

    return result


async def _resolve_rdap_ip(ip_addr):
    """RDAP IP lookup — with prefix caching + RETRY"""
    # Check cache
    # Use /24 for IPv4 as cache key
    if ':' not in ip_addr:
        prefix = '.'.join(ip_addr.split('.')[:3])
    else:
        prefix = ':'.join(ip_addr.split(':')[:4])

    if prefix in state.rdap_ip_cache:
        return state.rdap_ip_cache[prefix]

    # Try each RIR — with retry
    for attempt in range(RDAP_RETRY):
        for base_url in RDAP_IP_URLS:
            url = f"{base_url}/ip/{ip_addr}"
            try:
                async with state.aio_session.get(
                    url, timeout=aiohttp.ClientTimeout(total=RDAP_TIMEOUT),
                    allow_redirects=True, ssl=False
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        parsed = _parse_rdap_ip(data)
                        state.rdap_ip_cache[prefix] = parsed
                        return parsed
                    elif resp.status == 429:  # Rate limited
                        await asyncio.sleep(1.0 * (attempt + 1))
                        break  # Retry outer loop
                    elif resp.status == 301 or resp.status == 302:
                        continue
            except asyncio.TimeoutError:
                continue
            except Exception:
                continue

    state.rdap_ip_cache[prefix] = None
    return None


def _parse_rdap_ip(data):
    """Parse IP RDAP response"""
    if not data:
        return None

    result = {
        'handle': data.get('handle', ''),
        'parent_handle': data.get('parentHandle', ''),
        'name': data.get('name', ''),
        'whois_server': data.get('port43', ''),
        'type': 'ip network',
        'terms_of_service_url': '',
        'copyright_notice': '',
        'description': [],
        'last_changed_date': None,
        'registration_date': None,
        'expiration_date': None,
        'url': '',
        'rir': '',
        'entities': {},
        'country': data.get('country', ''),
        'ip_version': 4,
        'assignment_type': '',
        'network': {}
    }

    # Type/version
    if data.get('ipVersion') == 'v6':
        result['ip_version'] = 6

    # Type from data
    for t in data.get('type', []) if isinstance(data.get('type'), list) else [data.get('type', '')]:
        if t:
            result['assignment_type'] = t

    # Network CIDR
    start = data.get('startAddress', '')
    end = data.get('endAddress', '')
    cidr = data.get('cidr0_cidrs', [])
    if cidr and isinstance(cidr, list) and len(cidr) > 0:
        c = cidr[0]
        prefix_len = c.get('length', 0)
        prefix_addr = c.get('v4prefix', c.get('v6prefix', start))
        result['network'] = {
            'prefix_length': prefix_len,
            'network_address': prefix_addr,
            'netmask': '',
            'broadcast_address': end,
            'hostmask': ''
        }
        # Calculate netmask for IPv4
        if prefix_len and prefix_addr and ':' not in str(prefix_addr):
            try:
                import ipaddress
                net = ipaddress.ip_network(f"{prefix_addr}/{prefix_len}", strict=False)
                result['network']['netmask'] = str(net.netmask)
                result['network']['broadcast_address'] = str(net.broadcast_address)
                result['network']['hostmask'] = str(net.hostmask)
            except Exception:
                pass

    # Links
    for link in data.get('links', []):
        if link.get('rel') == 'self':
            result['url'] = link.get('href', '')
            href = link['href'].lower()
            if 'arin' in href:
                result['rir'] = 'arin'
            elif 'ripe' in href:
                result['rir'] = 'ripe'
            elif 'apnic' in href:
                result['rir'] = 'apnic'
            elif 'lacnic' in href:
                result['rir'] = 'lacnic'
            elif 'afrinic' in href:
                result['rir'] = 'afrinic'

    # Events
    for event in data.get('events', []):
        action = event.get('eventAction', '')
        date_str = event.get('eventDate', '')
        if action == 'registration':
            result['registration_date'] = date_str
        elif action == 'expiration':
            result['expiration_date'] = date_str
        elif action in ('last changed', 'last update'):
            result['last_changed_date'] = date_str

    # Entities
    for entity in data.get('entities', []):
        roles = entity.get('roles', [])
        entity_data = _parse_rdap_entity(entity)
        for role in roles:
            role_key = role.lower()
            if role_key not in result['entities']:
                result['entities'][role_key] = []
            result['entities'][role_key].append(entity_data)

    # Notices
    for notice in data.get('notices', []):
        title = notice.get('title', '').lower()
        if 'terms' in title:
            for link in notice.get('links', []):
                if not result['terms_of_service_url']:
                    result['terms_of_service_url'] = link.get('href', '')
        if 'copyright' in title:
            desc = notice.get('description', [])
            if desc:
                result['copyright_notice'] = ' '.join(desc)

    return result


# ============================================================
# MAIN RESOLVER: 1 domain
# ============================================================
async def resolve_domain(domain_name, category, source_file, loop):
    """Resolve tất cả data cho 1 domain — async"""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")

    record = {
        'domain_name': domain_name,
        'url': None,
        'source': source_file,
        'category': category,
        'sourced_on': now_str,
        'evaluated_on': None,
        'remarks': {
            'dns_evaluated_on': None,
            'rdap_evaluated_on': None,
            'tls_evaluated_on': None,
            'dns_had_no_ips': True
        },
        'dns': None,
        'rdap': None,
        'tls': None,
        'ip_data': None,
        'label': int(category) if category and str(category).isdigit() else 0
    }

    # 1. DNS (in thread executor)
    try:
        async with state.dns_sem:
            record['remarks']['dns_evaluated_on'] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
            dns_data, ips = await loop.run_in_executor(None, _resolve_dns_sync, domain_name)
            record['dns'] = dns_data
            record['remarks']['dns_had_no_ips'] = len(ips) == 0
            state.stats_dns_ok += 1
    except Exception:
        record['dns'] = None

    # 2. TLS + RDAP domain in parallel
    tls_task = None
    rdap_task = None

    async def do_tls():
        try:
            async with state.tls_sem:
                record['remarks']['tls_evaluated_on'] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
                tls_result = await loop.run_in_executor(None, _resolve_tls_sync, domain_name)
                record['tls'] = tls_result
                if tls_result:
                    state.stats_tls_ok += 1
        except Exception:
            record['tls'] = None

    async def do_rdap():
        try:
            async with state.rdap_sem:
                record['remarks']['rdap_evaluated_on'] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
                rdap_result = await _resolve_rdap_domain(domain_name)
                record['rdap'] = rdap_result
                if rdap_result:
                    state.stats_rdap_ok += 1
        except Exception:
            record['rdap'] = None

    # Run TLS + RDAP concurrently
    await asyncio.gather(do_tls(), do_rdap(), return_exceptions=True)

    # 3. IP RDAP (cho IPs tìm được từ DNS)
    if record['dns'] and not record['remarks']['dns_had_no_ips']:
        ips = []
        if record['dns'].get('A'):
            for ip in record['dns']['A']:
                ips.append({'ip': ip, 'from': 'A'})
        if record['dns'].get('AAAA'):
            for ip in record['dns']['AAAA']:
                ips.append({'ip': ip, 'from': 'AAAA'})

        if ips:
            record['ip_data'] = []
            ip_tasks = []

            for ip_info in ips:
                ip_entry = {
                    'ip': ip_info['ip'],
                    'from_record': ip_info['from'],
                    'remarks': {
                        'rdap_evaluated_on': None,
                        'asn_evaluated_on': None,
                        'geo_evaluated_on': None,
                        'rep_evaluated_on': None,
                        'icmp_evaluated_on': None,
                        'is_alive': False,
                        'average_rtt': None
                    },
                    'rdap': None,
                    'asn': None,
                    'geo': None,
                    'rep': None
                }
                record['ip_data'].append(ip_entry)

                async def resolve_ip_rdap(entry, ip):
                    try:
                        async with state.ip_rdap_sem:
                            entry['remarks']['rdap_evaluated_on'] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
                            entry['rdap'] = await _resolve_rdap_ip(ip)
                    except Exception:
                        entry['rdap'] = None

                ip_tasks.append(resolve_ip_rdap(ip_entry, ip_info['ip']))

            if ip_tasks:
                await asyncio.gather(*ip_tasks, return_exceptions=True)

    record['evaluated_on'] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
    return record


# ============================================================
# FILE I/O
# ============================================================
def load_domains_csv(input_file):
    """Load CSV có header domain,label"""
    domains = []
    with open(input_file, 'r', encoding='utf-8', errors='ignore', newline='') as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        domain_col = label_col = None
        for col in fieldnames:
            cl = col.strip().lower()
            if cl == 'domain':
                domain_col = col
            elif cl == 'label':
                label_col = col

        if domain_col is None:
            raise ValueError(f"Không tìm thấy cột 'domain'. Có: {fieldnames}")

        for row in reader:
            raw = row[domain_col].strip()
            label = row[label_col].strip() if label_col else '0'
            if not raw:
                continue
            match = re.search(HOSTNAME_REGEX, raw, re.IGNORECASE)
            if match:
                domains.append((match.group(0).lower(), label))
    return domains


def get_jsonl_path(output_dir):
    return os.path.join(output_dir, 'results.jsonl')


def get_done_path(output_dir):
    return os.path.join(output_dir, 'done_domains.txt')


def load_done_domains(output_dir):
    """Load set of done domains from done file"""
    done_path = get_done_path(output_dir)
    done = set()
    if os.path.exists(done_path):
        with open(done_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    done.add(line)
    return done


def append_results(output_dir, records, done_domains_set):
    """Append results to JSONL + update done set"""
    jsonl_path = get_jsonl_path(output_dir)
    done_path = get_done_path(output_dir)

    with open(jsonl_path, 'a', encoding='utf-8') as jf, \
         open(done_path, 'a', encoding='utf-8') as df:
        for record in records:
            jf.write(json.dumps(record, ensure_ascii=False, default=str) + '\n')
            df.write(record['domain_name'] + '\n')
            done_domains_set.add(record['domain_name'])


# ============================================================
# MAIN
# ============================================================
async def scan_all(args):
    """Main scanning loop — semaphore-bounded concurrency"""
    loop = asyncio.get_event_loop()

    # CRITICAL: Explicit thread pool for DNS/TLS blocking calls
    from concurrent.futures import ThreadPoolExecutor
    thread_pool = ThreadPoolExecutor(max_workers=200)
    loop.set_default_executor(thread_pool)

    # Tạo output directory
    os.makedirs(args.output, exist_ok=True)

    # Load domains
    print(f"\n[*] Loading domains from: {args.input}")
    all_pairs = load_domains_csv(args.input)
    if args.limit > 0:
        all_pairs = all_pairs[:args.limit]
    print(f"    Total: {len(all_pairs):,} domains")

    # Load done
    done_domains = load_done_domains(args.output)
    initial_done_count = len(done_domains)
    if done_domains:
        print(f"    Resume: {initial_done_count:,} domains already done")

    # Filter pending
    pending = [(d, l) for d, l in all_pairs if d not in done_domains]
    print(f"    Pending: {len(pending):,} domains")
    print(f"    Workers: {args.workers} concurrent")
    print(f"    Thread pool: 200 threads (DNS/TLS)")
    print(f"    Checkpoint: every {CHECKPOINT_EVERY} domains")
    print(f"    uvloop: {'YES' if USING_UVLOOP else 'NO'}")

    if not pending:
        print("\n[OK] All done! Converting to final JSON...")
        return

    state.total = len(all_pairs)
    state.start_time = time.time()

    # Init semaphores
    state.dns_sem = asyncio.Semaphore(min(args.workers, SEM_DNS))
    state.tls_sem = asyncio.Semaphore(min(args.workers, SEM_TLS))
    state.rdap_sem = asyncio.Semaphore(min(args.workers, SEM_RDAP))
    state.ip_rdap_sem = asyncio.Semaphore(min(args.workers, SEM_IP_RDAP))

    # Overall concurrency limiter
    concurrency_sem = asyncio.Semaphore(args.workers)

    # aiohttp session (shared connection pool)
    connector = aiohttp.TCPConnector(
        limit=args.workers,
        limit_per_host=10,
        ttl_dns_cache=300,
        enable_cleanup_closed=True,
        force_close=False,
    )
    state.aio_session = aiohttp.ClientSession(
        connector=connector,
        headers={'Accept': 'application/json', 'User-Agent': 'DomainRadar-Scanner/2.0'}
    )

    source_file = 'kaggle_csv_dataset'
    batch_buffer = []
    buffer_lock = asyncio.Lock()

    # Signal handler
    def handle_signal():
        state.interrupted = True
        print(f"\n\n[!] Interrupt! Saving checkpoint...")

    loop.add_signal_handler(signal.SIGINT, handle_signal)
    try:
        loop.add_signal_handler(signal.SIGTERM, handle_signal)
    except Exception:
        pass

    print(f"\n>>> Starting scan...\n")

    async def process_one(domain, label):
        """Process a single domain with concurrency control"""
        if state.interrupted:
            return

        async with concurrency_sem:
            if state.interrupted:
                return
            try:
                record = await asyncio.wait_for(
                    resolve_domain(domain, label, source_file, loop),
                    timeout=DOMAIN_TIMEOUT
                )
                async with buffer_lock:
                    batch_buffer.append(record)
                    state.completed += 1
            except asyncio.TimeoutError:
                now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
                empty = {
                    'domain_name': domain, 'url': None,
                    'source': source_file, 'category': label,
                    'sourced_on': now_str, 'evaluated_on': now_str,
                    'remarks': {
                        'dns_evaluated_on': now_str,
                        'rdap_evaluated_on': now_str,
                        'tls_evaluated_on': now_str,
                        'dns_had_no_ips': True,
                        'error': 'TIMEOUT'
                    },
                    'dns': None, 'rdap': None, 'tls': None,
                    'ip_data': None,
                    'label': int(label) if label and str(label).isdigit() else 0
                }
                async with buffer_lock:
                    batch_buffer.append(empty)
                    state.failed += 1
            except Exception as e:
                now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
                empty = {
                    'domain_name': domain, 'url': None,
                    'source': source_file, 'category': label,
                    'sourced_on': now_str, 'evaluated_on': now_str,
                    'remarks': {
                        'dns_evaluated_on': now_str,
                        'rdap_evaluated_on': now_str,
                        'tls_evaluated_on': now_str,
                        'dns_had_no_ips': True,
                        'error': str(e)[:200]
                    },
                    'dns': None, 'rdap': None, 'tls': None,
                    'ip_data': None,
                    'label': int(label) if label and str(label).isdigit() else 0
                }
                async with buffer_lock:
                    batch_buffer.append(empty)
                    state.failed += 1

    async def progress_reporter():
        """Background task to print progress and save checkpoints"""
        while not state.interrupted:
            await asyncio.sleep(3)
            current_processed = state.completed + state.failed
            total_done = initial_done_count + current_processed
            if total_done == 0:
                continue
            elapsed = time.time() - state.start_time
            rate = current_processed / max(elapsed, 1)
            remaining = max(0, len(pending) - current_processed) / max(rate, 0.01)
            pct = min(100.0, total_done / max(state.total, 1) * 100)

            print(
                f"\r  [{total_done:>8,}/{state.total:,}] {pct:5.1f}% "
                f"| {rate:.1f} dom/s "
                f"| ETA: {remaining/3600:.1f}h "
                f"| DNS:{state.stats_dns_ok} TLS:{state.stats_tls_ok} RDAP:{state.stats_rdap_ok} "
                f"| fail:{state.failed}",
                end='', flush=True
            )

            # Auto-checkpoint
            async with buffer_lock:
                if len(batch_buffer) >= CHECKPOINT_EVERY:
                    append_results(args.output, batch_buffer, done_domains)
                    jsize = os.path.getsize(get_jsonl_path(args.output)) / (1024*1024)
                    print(f"\n   [SAVE] Checkpoint: {len(done_domains):,} total | JSONL: {jsize:.1f} MB")
                    batch_buffer.clear()

    try:
        # Start progress reporter
        progress_task = asyncio.ensure_future(progress_reporter())

        # Process ALL pending domains via semaphore-bounded tasks
        CHUNK = 5000  # Submit in chunks to avoid creating 2M tasks at once
        for chunk_start in range(0, len(pending), CHUNK):
            if state.interrupted:
                break
            chunk = pending[chunk_start:chunk_start + CHUNK]
            tasks = [process_one(d, l) for d, l in chunk]
            await asyncio.gather(*tasks, return_exceptions=True)

        # Stop progress reporter
        progress_task.cancel()
        try:
            await progress_task
        except asyncio.CancelledError:
            pass

    except KeyboardInterrupt:
        state.interrupted = True
        print(f"\n\n[!] KeyboardInterrupt!")
    except Exception as e:
        print(f"\n\n[ERROR] {e}")
        traceback.print_exc()
    finally:
        # Save remaining
        async with buffer_lock:
            if batch_buffer:
                append_results(args.output, batch_buffer, done_domains)
                print(f"\n   [SAVE] Final checkpoint: {len(batch_buffer)} records saved")
                batch_buffer.clear()

        # Close session & thread pool
        if state.aio_session:
            await state.aio_session.close()
        thread_pool.shutdown(wait=False)

    # Stats
    elapsed = time.time() - state.start_time
    total_processed = state.completed + state.failed
    print(f"\n\n{'=' * 65}")
    print(f"  SCAN RESULTS")
    print(f"{'=' * 65}")
    print(f"  Total domains:    {state.total:>10,}")
    print(f"  Already done:     {initial_done_count:>10,}")
    print(f"  Processed now:    {total_processed:>10,}")
    print(f"  Succeeded:        {state.completed:>10,}")
    print(f"  Failed/timeout:   {state.failed:>10,}")
    print(f"  Time:             {elapsed/3600:>10.2f} hours")
    print(f"  Rate:             {total_processed/max(elapsed,1):>10.1f} dom/s")
    print(f"  DNS OK:           {state.stats_dns_ok:>10,}")
    print(f"  TLS OK:           {state.stats_tls_ok:>10,}")
    print(f"  RDAP OK:          {state.stats_rdap_ok:>10,}")
    jsonl_path = get_jsonl_path(args.output)
    if os.path.exists(jsonl_path):
        size_mb = os.path.getsize(jsonl_path) / (1024 * 1024)
        print(f"  JSON size:        {size_mb:>10.1f} MB")
    print(f"{'=' * 65}")

    if state.interrupted:
        print("  [!] Interrupted. Run again with same args to resume!")
    else:
        print("  [OK] SCAN COMPLETED!")
    print(f"{'=' * 65}")


def main():
    parser = argparse.ArgumentParser(
        description='DomainRadar Async Scanner — WSL2 Edition'
    )
    parser.add_argument('--input', '-i', required=True,
                        help='File CSV input (header: domain,label)')
    parser.add_argument('--output', '-o', required=True,
                        help='Output directory (sẽ tạo results.jsonl bên trong)')
    parser.add_argument('--workers', '-w', type=int, default=MAX_WORKERS,
                        help=f'Concurrent domains (mặc định {MAX_WORKERS})')
    parser.add_argument('--limit', '-n', type=int, default=0,
                        help='Giới hạn số domains (0 = tất cả)')
    args = parser.parse_args()

    print("=" * 65)
    print("  DOMAINRADAR ASYNC SCANNER — WSL2 EDITION")
    print("=" * 65)

    asyncio.run(scan_all(args))


if __name__ == '__main__':
    main()
