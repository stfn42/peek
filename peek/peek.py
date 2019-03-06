# -*- coding: utf-8 -*-
"""peek.py

`peek` is a scanner for common misconfigurations in http servers.
It runs a series of simple checks using HTTP HEAD requests.

Example:
        $ python peek.py -u https://www.example.com


CAUTION: Hacky code. Here be dragons.
Use at your own risk. Pull requests welcome.

Todo:
    * Full checks for CSP, Feature-Policy and Referrer-Policy
    (currently only checks for existence)
    * Refactor hacky code (may or may not happen...)
"""

import argparse
import socket
import urllib.parse
import validators
import requests
import re
import json
from tld import get_tld


def parse_args():
    parser = argparse.ArgumentParser(
        description='peek - quick http analysis',
        epilog='Ping me on Twitter @stfn42 if you get stuck.')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-t',
                       help='target a single host',
                       dest="targethost")

    group.add_argument('-l',
                       help='import a list of targets from a file',
                       dest="listfile")

    parser.add_argument('--privacy',
                        help='Disables checks against public APIs',
                        action="store_true", dest="privacy")

    parser.add_argument('--version', action='version', version='%(prog)s 0.1')
    return parser.parse_args()


def validate_target(target):
    # Check if URL is valid
    if not validators.url(target):
        print('[!] %s is not a valid URL.' % target)
        return False

    try:
        __host = urllib.parse.urlparse(target).netloc
        socket.gethostbyname(__host)
    except socket.gaierror:
        print('[!] %s cannot be resolved.' % target)
        return False

    return True


def load_targets_from_file(listfile):
    with open(listfile) as file:
        targets = file.read().splitlines()
    return targets


def main():
    print("peek.py")
    print("-------")
    args = parse_args()

    # Populate target list
    __targets = []

    # Handle
    if args.targethost:
        __targets.append(args.targethost)
    elif args.listfile:
        __targets = load_targets_from_file(args.listfile)

    targets = [t for t in __targets if validate_target(t)]

    for t in targets:
        f = TargetUrl(t)
        f.run_checks(args.privacy)
        print()

class TargetUrl:
    # Prepare regex on class level - not sure if this works as intended.
    r_hsts_maxage = re.compile(r'max-age=(\"?\d+\"?)', re.IGNORECASE)
    r_hsts_includesubdomains = re.compile('includeSubDomains', re.IGNORECASE)
    r_hsts_preload = re.compile('preload', re.IGNORECASE)
    r_sh_xss_block = re.compile('mode=(\"?block\"?)', re.IGNORECASE)
    r_xfo_allowfrom = re.compile('ALLOW-FROM', re.IGNORECASE)

    c_max_age_recommended = 10368000


    def __init__(self, url):
        self.url = url
        self.headers = self.fetch_headers()
        self.scheme = urllib.parse.urlparse(self.url).scheme

    def fetch_headers(self):
        custom_headers = {'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; '
                                  'x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                                  'Chrome/71.0.3578.98 Safari/537.36')
                          }

        r = requests.head(self.url, headers=custom_headers)
        if r:
            return r.headers
        else:
            print('[!] Error getting headers.')
            return False

    def run_checks(self, privacy):
        print('[+] Started check on', self.url)
        self.check_hsts(privacy)
        self.check_simple_headers()

    def check_hsts(self, privacy=False):
        if 'Strict-Transport-Security' in self.headers and self.scheme == 'http':
            print('[-] Strict-Transport-Security *must not* be set via HTTP!')
            # No return here, we'll run tests either way.

        if 'Strict-Transport-Security' in self.headers:
            h = self.headers['Strict-Transport-Security']
            print('[>] HSTS Header:', h)

            # Check for bad max-age values
            res = TargetUrl.r_hsts_maxage.findall(h)
            if res:
                if len(res) > 1:
                    print('[-] HSTS: Multiple max-age directives found. Will use the last one for checks.')
                max_age = int(res[-1])
                if 0 < max_age < TargetUrl.c_max_age_recommended:
                    print('[-] HSTS: max-age is set to %i, should be %i or higher.' % (max_age, TargetUrl.c_max_age_recommended))
                elif max_age == 0:
                    print('[-] HSTS: max-age is set to 0. This will instruct the browser to delete HSTS cache entry.')

            # Check for includeSubdomains
            res = TargetUrl.r_hsts_includesubdomains.search(h)
            if not res:
                print('[-] HSTS: includeSubDomains directive is missing.')

            # Check for preload
            res = TargetUrl.r_hsts_preload.search(h)
            if not res:
                print('[-] HSTS: preload directive is missing.')
            elif res and not privacy:
                fld = get_tld(self.url, as_object=True).fld
                __r = requests.get('https://hstspreload.com/api/v1/status/%s' % fld, headers={'User-Agent': 'peek'})
                if __r:
                    status = json.loads(__r.text)
                    print('[*] HSTS: Preload Status:')
                    print('\t[%s] Chrome' % ('X' if status['chrome'] else ' '))
                    print('\t[%s] Firefox' % ('X' if status['firefox'] else ' '))
                    print('\t[%s] Tor' % ('X' if status['tor'] else ' '))
                    if not status['chrome'] and not status['firefox'] and not status['tor']:
                        print('[-] HSTS: preload directive was set recently or was not submitted.')
                else:
                    print('[!] Could not get HSTS Preload Status via API')

            else:
                print('[-] HSTS: max-age directive is missing.')
        elif self.scheme == 'https':
            # Only report this if it's observed via https
            print('[-] Strict-Transport-Security header is not set.')

    def check_simple_headers(self):
        if 'X-XSS-Protection' in self.headers:
            h = self.headers['X-XSS-Protection']
            print('[>] X-XSS-Protection Header:', h)
            res = TargetUrl.r_sh_xss_block.search(h)
            if not res:
                print('[-] Security Headers: X-XSS-Protection mode is not set to "block"')
        else:
            print('[-] Security Headers: X-XSS-Protection header is not set.')

        if 'X-Content-Type-Options' in self.headers:
            h = self.headers['X-Content-Type-Options']
            print('[>] X-Content-Type-Options Header:', h)
            if not h == 'nosniff':
                print('[-] Security Headers: X-Content-Type-Options header is not set to "nosniff".')
        else:
            print('[-] Security Headers: X-Content-Type-Options header is not set.')

        if 'X-Frame-Options' in self.headers:
            h = self.headers['X-Frame-Options']
            print('[>] X-Frame-Options Header:', h)
            res = TargetUrl.r_xfo_allowfrom.search(h)
            if res:
                print('[-] Security Headers: X-Frame-Options allows framing via ALLOW-FROM.')
        else:
            # It's debatable if this should be reported considering frame-ancestors in CSP
            print('[-] Security Headers: X-Frame-Options header is not set.')

        # Pure existence checks, to be improved:
        exist_headers = ['Content-Security-Policy', 'Referrer-Policy', 'Feature-Policy', 'Expect-CT']

        for __h in exist_headers:
            if __h in self.headers:
                h = self.headers[__h]
                print('[>] %s Header: %s' % (__h, h))
            else:
                print('[-] Security Headers: %s header is not set.' % (__h))

# Call main function...
main()