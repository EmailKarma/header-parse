#!/usr/bin/env python3
"""SenderFrom email header diagnostic v0.4. Offline, standard library only.

Route assessments are heuristics, not verification of header authenticity.
"""
import argparse
from collections import defaultdict
from datetime import datetime, timezone
from email.parser import HeaderParser
from email.policy import default
from email.utils import parsedate_to_datetime, getaddresses
import ipaddress
import json
import re
import sys
from pathlib import Path

VERSION = '0.4.0'
# Extend the registry without changing the reporting code. Keys are case-insensitive.
INTERESTING_HEADERS = {
    'tracking': ['X-250ok-CID', 'X-rpcampaign', 'rpcampaign', 'X-PVIQ', 'X-Campaign-ID',
                 'X-CampaignID', 'X-Job', 'X-EMarSys-Identify', 'X-BPS2', 'X-Kmail-Message',
                 'X-Mailgun-Variables'],
    'feedback': ['X-Feedback-ID', 'Feedback-ID', 'X-Report-Abuse-To', 'List-Unsubscribe'],
    'software': ['X-Mailer', 'User-Agent'],
    'account': ['X-AuthUser'],
    'provider': ['X-Mailgun-Dkim', 'X-Sender-Id', 'X-MailChannels-SenderId',
                 'X-MailChannels-Auth-Id', 'X-Drop-Whispering', 'X-MC-Loop-Signature',
                 'X-MC-Ingress-Time'],
}
PROVIDER_SIGNALS = {
    'MailChannels': {'x-mailchannels-senderid', 'x-mailchannels-auth-id', 'x-mc-ingress-time'},
    'Mailgun': {'x-mailgun-dkim', 'x-mailgun-variables'},
}
IP_PATTERN = re.compile(r'(?<![\w.:])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')
BRACKET_IP = re.compile(r'\[(?:IPv6:)?([^\]]+)\]', re.I)
FROM_RE = re.compile(r'^\s*from\s+([^\s(]+)', re.I)
BY_RE = re.compile(r'\bby\s+([^\s(;]+)', re.I)
WITH_RE = re.compile(r'\bwith\s+(ESMTPSA|ESMTPS|ESMTPA|ESMTP|SMTPS|SMTP|LMTP|QMQP|LOCAL|HTTPS)\b', re.I)
DATE_RE = re.compile(r';\s*(.+)$', re.S)
KV_RE = re.compile(r'(?<![\w.-])([\w.-]+)\s*=\s*([^;\s]+)')


def compact(s):
    return re.sub(r'\s+', ' ', str(s or '')).strip()


def field_values(msg, key):
    return [compact(str(v)) for v in msg.get_all(key, [])]


def first(msg, key, fallback='(not present)'):
    vals = field_values(msg, key)
    return vals[0] if vals else fallback


def ip_type(value):
    try:
        ip = ipaddress.ip_address(value)
        if ip in ipaddress.ip_network('100.64.0.0/10'):
            return 'shared/CGNAT'
        if ip.is_loopback:
            return 'loopback'
        if ip.is_private:
            return 'private/non-global'
        if ip.is_link_local:
            return 'link-local'
        if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return 'special/non-global'
        return 'public' if ip.is_global else 'non-global'
    except ValueError:
        return 'invalid'


def extract_ips(text):
    found = []
    for m in BRACKET_IP.finditer(text):
        candidate = m.group(1)
        try:
            ipaddress.ip_address(candidate)
            if candidate not in found:
                found.append(candidate)
        except ValueError:
            pass
    for m in IP_PATTERN.finditer(text):
        candidate = m.group()
        try:
            ipaddress.ip_address(candidate)
            if candidate not in found:
                found.append(candidate)
        except ValueError:
            pass
    return found


def parse_hop(raw, idx):
    text = compact(raw)
    # Split off date first to avoid confusing its tokens with routing fields.
    match = DATE_RE.search(text)
    routing = text[:match.start()] if match else text
    date = None
    if match:
        try:
            date = parsedate_to_datetime(match.group(1).strip())
            if date.tzinfo:
                date = date.astimezone(timezone.utc)
            else:
                date = None
        except (ValueError, TypeError, IndexError):
            pass
    fm = FROM_RE.search(routing)
    bm = BY_RE.search(routing)
    wm = WITH_RE.search(routing)
    from_host = fm.group(1).strip('[]') if fm else None
    by_host = bm.group(1).strip('[]') if bm else None
    # IPs in the FROM clause are peer claims made by the receiving host.
    from_segment = routing[fm.end():bm.start()] if fm and bm and bm.start() > fm.end() else ''
    ips = extract_ips(from_segment)
    if from_host:
        try:
            ipaddress.ip_address(from_host)
            if from_host not in ips:
                ips.insert(0, from_host)
        except ValueError:
            pass
    # Handle 'from 178.13.85.69 (EHLO gmx.at)' and 'from ... [IPv6:...]'.
    peer = ips[0] if ips else None
    # BY may itself be an IP literal; useful for the next hop comparison.
    by_ip = None
    if by_host:
        try:
            ipaddress.ip_address(by_host)
            by_ip = by_host
        except ValueError:
            pass
    tls = re.search(r'\bTLSv?(1[._][0-3])\b', routing, re.I)
    cipher = re.search(r'\bcipher[=\s]+([\w-]+)', routing, re.I)
    return {'n': idx, 'raw': text, 'from': from_host, 'by': by_host, 'peer': peer,
            'by_ip': by_ip, 'protocol': wm.group(1).upper() if wm else None,
            'time': date, 'tls': tls.group(1).replace('_', '.') if tls else None,
            'cipher': cipher.group(1) if cipher else None}


def host_equal(a, b):
    return bool(a and b and a.rstrip('.').lower() == b.rstrip('.').lower())


def pair_evidence(older, newer, tolerance=300):
    """Evaluate only observable continuity. Mismatch alone is never a forgery verdict."""
    reasons = []
    positives = []
    if host_equal(older['by'], newer['from']):
        positives.append('previous receiving hostname matches next sending hostname')
    if older['by_ip'] and newer['peer'] and older['by_ip'] == newer['peer']:
        positives.append('previous receiving IP matches next sending IP')
    if older['time'] and newer['time']:
        delta = (newer['time'] - older['time']).total_seconds()
        if delta < -tolerance:
            reasons.append(f'chronology reverses by {abs(delta):.0f}s (over {tolerance}s tolerance)')
        elif delta < 0:
            positives.append('timestamps differ only within clock-skew tolerance')
        else:
            positives.append('chronological order consistent')
    if not any('matches' in p for p in positives):
        reasons.append('no direct hostname/IP continuity visible (may be normal NAT or omitted trace)')
    # Time contradiction is stronger than a name mismatch.
    strong = any('chronology reverses' in r for r in reasons)
    return {'older': older['n'], 'newer': newer['n'], 'positive': positives,
            'concerns': reasons, 'strong': strong,
            'status': 'SUSPICIOUS' if strong else ('PLAUSIBLE' if len(reasons) > 0 else 'CONSISTENT')}


def auth_results(msg):
    out = []
    for value in field_values(msg, 'Authentication-Results'):
        evaluator = value.split(';', 1)[0].strip()
        results = re.findall(r'\b(spf|dkim|dmarc|arc)\s*=\s*([\w-]+)', value, re.I)
        out.append((evaluator, results, value))
    return out


def tags(value):
    return {m.group(1).lower(): m.group(2) for m in KV_RE.finditer(value)}


def print_section(title):
    print('\n' + title + '\n' + '-' * len(title))


def display_registry(msg):
    titles = {'tracking': 'TRACKING / CAMPAIGN IDs', 'feedback': 'FEEDBACK / ABUSE',
              'software': 'SOFTWARE / CLIENT', 'account': 'SENDER / ACCOUNT IDENTIFIERS',
              'provider': 'PROVIDER METADATA'}
    for group, names in INTERESTING_HEADERS.items():
        matches = [(name, field_values(msg, name)) for name in names if field_values(msg, name)]
        if not matches:
            continue
        print_section(titles[group])
        if group == 'provider':
            present = {n.lower() for n, _ in matches}
            signals = [provider for provider, keys in PROVIDER_SIGNALS.items() if keys & present]
            if signals:
                print('Provider signals: ' + ', '.join(signals) + ' (header claims; not verified)')
        for name, vals in matches:
            for value in vals:
                if name.lower() == 'x-mailgun-variables':
                    try:
                        parsed = json.loads(value)
                        if isinstance(parsed, dict):
                            print(f'{name}: JSON object ({len(parsed)} keys; values hidden by default)')
                            continue
                    except (ValueError, TypeError):
                        pass
                    print(f'{name}: {value[:180]}' + ('… [truncated]' if len(value) > 180 else ''))
                else:
                    print(f'{name}: {value[:350]}' + ('… [truncated]' if len(value) > 350 else ''))
                if name.lower() == 'x-mc-ingress-time' and value.isdigit() and len(value) == 13:
                    try:
                        print('  Apparent Unix ms (UTC): ' + datetime.fromtimestamp(int(value) / 1000, timezone.utc).isoformat())
                    except (ValueError, OverflowError, OSError):
                        pass


def analyze_route(hops, msg, tolerance=300):
    pairs = [pair_evidence(hops[i], hops[i+1], tolerance) for i in range(len(hops)-1)]
    # Trust boundary is provisional: cannot authenticate Received headers from a copied text file.
    auth = auth_results(msg)
    evaluator = auth[0][0] if auth else None
    # Search newest -> oldest for first public peer whose receiving host is consistent
    # with the evaluator's organization or a directly adjacent internal receiver trace.
    candidate = None
    for i in range(len(hops)-1, -1, -1):
        hop = hops[i]
        if hop['peer'] and ip_type(hop['peer']) == 'public':
            candidate = i
            break
    # Multiple gaps only produce a likely-fabricated assessment when concentrated
    # below a receiver-consistent ingress; otherwise insufficient corroboration.
    gaps = [p for p in pairs if any('no direct hostname/IP continuity' in c for c in p['concerns'])]
    inversions = [p for p in pairs if p['strong']]
    # Consecutive gaps matter; scattered gaps are routine at provider boundaries.
    run = longest_run = 0
    for p in pairs:
        if any('no direct hostname/IP continuity' in c for c in p['concerns']):
            run += 1
            longest_run = max(longest_run, run)
        else:
            run = 0
    print_section('LIKELY SENDING IP')
    if candidate is None:
        print('No public peer IP found in Received headers.')
    else:
        hop = hops[candidate]
        ip = hop['peer']
        print(f'IP: {ip} (hop {hop["n"]}, receiving host: {hop["by"] or "unknown"})')
        corroborations = []
        for val in field_values(msg, 'Received-SPF'):
            if ip in val:
                corroborations.append('Received-SPF mentions the same IP')
        for val in field_values(msg, 'X-Originating-IP'):
            if ip in val:
                corroborations.append('X-Originating-IP mentions the same IP (untrusted claim)')
        if auth:
            for _, _, raw in auth:
                if ip in raw:
                    corroborations.append('Authentication-Results mentions the same IP')
                    break
        # Never overstate origin; select the oldest corroborated public ingress if available.
        print('Interpretation: newest public SMTP peer visible before receiver-local processing;')
        print('  this is not necessarily the device that composed the message.')
        print('Confidence: ' + ('MODERATE (receiver-consistent, not verified)' if corroborations else 'LOW (Received claim only)'))
        for evidence in corroborations:
            print('  - ' + evidence)
    print_section('ROUTING ASSESSMENT')
    if inversions:
        print('SUSPICIOUS: one or more time-order contradictions exceed clock-skew tolerance.')
    if longest_run >= 3 and candidate is not None and candidate >= 2:
        print('HIGHLY SUSPICIOUS PATTERN: multiple uncorroborated upstream handoffs.')
        print('  Likely explanation: inserted/fabricated trace is possible; not proven.')
    elif gaps:
        print('PLAUSIBLE / UNVERIFIED: visible handoff gaps; not sufficient to infer fabrication.')
    else:
        print('PLAUSIBLE: no material continuity anomalies detected.')
    return pairs


def diagnose(msg, path, tolerance):
    hops = [parse_hop(v, i) for i, v in enumerate(reversed(field_values(msg, 'Received')), 1)]
    print(f'EMAIL HEADER DIAGNOSTIC v{VERSION}')
    print(f'Source: {path}')
    print(f'Header fields: {len(list(msg.raw_items()))} | Received hops: {len(hops)}')
    print_section('IDENTITIES')
    for key in ['From', 'X-Original-From', 'Return-Path', 'Reply-To', 'To', 'Delivered-To', 'Subject', 'Message-ID', 'Date']:
        vals = field_values(msg, key)
        if vals:
            for val in vals:
                print(f'{key}: {val[:300]}')
    print_section('AUTHENTICATION HISTORY (RECEIVER ASSERTIONS)')
    auth = auth_results(msg)
    if not auth:
        print('No Authentication-Results headers.')
    for evaluator, results, raw in auth:
        print()
        print('Evaluator: ' + (evaluator or '(unknown)'))
        if not results:
            print('  No parsed authentication methods')
            continue
        # A DKIM result belongs to one signature; retain all of them.
        dkim_matches = list(re.finditer(r'\bdkim\s*=\s*([\w-]+)([^;]*)', raw, re.I))
        if dkim_matches:
            for match in dkim_matches:
                fragment = match.group(2)
                domain = re.search(r'header\.d\s*=\s*([^\s;]+)', fragment, re.I)
                identity = re.search(r'header\.i\s*=\s*([^\s;]+)', fragment, re.I)
                selector = re.search(r'header\.s\s*=\s*([^\s;]+)', fragment, re.I)
                parts = ['DKIM ' + match.group(1).upper()]
                if domain:
                    parts.append('domain=' + domain.group(1))
                elif identity:
                    parts.append('identity=' + identity.group(1))
                if selector:
                    parts.append('selector=' + selector.group(1))
                print('  ' + ' '.join(parts))
        else:
            for method, result in results:
                if method.lower() == 'dkim':
                    print('  DKIM ' + result.upper())
        for method, result in results:
            if method.lower() != 'dkim':
                print('  ' + method.upper() + ' ' + result.upper())
    signatures = field_values(msg, 'DKIM-Signature')
    if signatures:
        print_section('DKIM SIGNATURES (NOT CRYPTOGRAPHICALLY VERIFIED)')
        for i, signature in enumerate(signatures, 1):
            t = tags(signature)
            print(f"{i}. d={t.get('d','?')} s={t.get('s','?')} a={t.get('a','?')}")
    if field_values(msg, 'DKIM2-Signature') or field_values(msg, 'Message-Instance') or field_values(msg, 'X-DKIM2-Info'):
        print_section('DKIM2 EXPERIMENT (NOT VERIFIED)')
        for key in ['X-DKIM2-Info', 'DKIM2-Signature', 'Message-Instance']:
            for val in field_values(msg, key):
                t = tags(val)
                if key == 'DKIM2-Signature':
                    print(f"{key}: d={t.get('d','?')} i={t.get('i','?')} m={t.get('m','?')} [signature material omitted]")
                elif key == 'Message-Instance':
                    print(f"{key}: m={t.get('m','?')} [hashes omitted]")
                else:
                    print(f'{key}: {val[:220]}')
    if field_values(msg, 'ARC-Seal'):
        print_section('ARC (NOT CRYPTOGRAPHICALLY VERIFIED)')
        for val in field_values(msg, 'ARC-Seal'):
            t = tags(val)
            print(f"set i={t.get('i','?')} d={t.get('d','?')} cv={t.get('cv','?')}")
    if field_values(msg, 'List-Id') or field_values(msg, 'X-Mailman-Version'):
        print_section('MAILING LIST')
        for key in ['List-Id', 'X-Mailman-Version', 'Precedence']:
            for val in field_values(msg, key):
                print(f'{key}: {val}')
    display_registry(msg)
    print_section('DELIVERY FLOW (OLDEST -> NEWEST; ALL HOPS ARE HEADER CLAIMS)')
    if not hops:
        print('No Received headers.')
    pair_findings = [pair_evidence(hops[i], hops[i + 1], tolerance) for i in range(len(hops) - 1)]
    for hop in hops:
        peer = hop['peer'] or 'not identified'
        print(f"[{hop['n']}] {hop['from'] or '(local injection)'} -> {hop['by'] or '(unknown receiver)'}")
        print(f"    Peer: {peer}" + (f" ({ip_type(peer)})" if hop['peer'] else ''))
        if hop['protocol']:
            print('    Protocol: ' + hop['protocol'])
        if hop['tls'] or hop['cipher']:
            print('    Transport: ' + ' / '.join(filter(None, [f"TLS {hop['tls']}" if hop['tls'] else None, hop['cipher']])))
        if hop['time']:
            print('    Time: ' + hop['time'].isoformat())
        if hop['n'] <= len(pair_findings):
            finding = pair_findings[hop['n'] - 1]
            print(f"    Hops {finding['older']} -> {finding['newer']}: {finding['status']}")
            for reason in finding['concerns'] or finding['positive'][:2]:
                print('    - ' + reason)
        if hop['n'] < len(hops):
            print()
    if hops:
        analyze_route(hops, msg, tolerance)
    print_section('LIMITATIONS')
    print('Header-only offline analysis. No DNS, PTR, SPF, DKIM, DKIM2 or ARC verification.')
    print('Received and Authentication-Results can be forged before the receiving trust boundary.')
    print('Do not interpret hostname mismatches or authentication failure alone as proof of forgery.')


def main(argv=None):
    parser = argparse.ArgumentParser(description='SenderFrom header diagnostic (offline)')
    parser.add_argument('input', nargs='?', help='header file (or --filename.txt legacy form)')
    parser.add_argument('--file', dest='file', help='header file path')
    parser.add_argument('--all-headers', action='store_true', help='print raw parsed fields after diagnosis')
    parser.add_argument('--clock-skew', type=int, default=300, help='allowed timestamp skew in seconds (default 300)')
    parser.add_argument('--version', action='version', version=VERSION)
    args, unknown = parser.parse_known_args(argv)
    path = args.file or args.input
    if unknown:
        if not path and len(unknown) == 1 and unknown[0].startswith('--') and '=' not in unknown[0]:
            path = unknown[0][2:]
        else:
            parser.error('unrecognized arguments: ' + ' '.join(unknown))
    if args.clock_skew < 0:
        parser.error('--clock-skew must be nonnegative')
    if path:
        try:
            raw = Path(path).read_text(encoding='utf-8-sig', errors='replace')
        except OSError as e:
            parser.error(str(e))
    else:
        if sys.stdin.isatty():
            parser.error('provide a file or pipe raw headers on stdin')
        raw = sys.stdin.read()
        path = '<stdin>'
    # Stop at the first blank line, if a full RFC 5322 message is provided.
    header_text = re.split(r'\r?\n\r?\n', raw, maxsplit=1)[0]
    msg = HeaderParser(policy=default).parsestr(header_text)
    diagnose(msg, path, args.clock_skew)
    if args.all_headers:
        print_section('ALL HEADERS')
        for key, value in msg.raw_items():
            print(f'{key}: {compact(value)}')


if __name__ == '__main__':
    main()
