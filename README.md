## About peek
_peek_ is a simple scanner that checks one or more URLs for common issues with security headers. Its core implementation was checking for common HSTS issues, but has been extended to include other common headers. The level of scrutiny with which the single headers are treated varies greatly at this point.

## What is _peek_ looking for?

### Strict-Transport-Security
* Is a HSTS header present? This is self-explanatory, I guess.
* Is max-age set too short? Sometimes sites use very short values for this, such as 3600 or even 60. This rarely ever makes sense. A value of 0, rendering HSTS inactive, is also observed quite commonly.
* Is includeSubDomains being used? Deploying SSL across all subdomains is not always possible, but in most cases at least desirable. It is also a prerequisite for inclusion in Chromium's preload list.
* Is preload being used and if so, has it been included in the respective lists shipped with browsers? It is quite common for hosts to advertise preload in their HSTS headers while their owners have never actually submitted the domain for inclusion.

For some information on these issues, please see https://medium.com/@stfn42/http-strict-transport-security-be24a6a6872e

### X-Xss-Protection
* Is the X-Xss-Protection header present?
* Is mode set to block? It is quite common to see X-Xss-Protection set to 1, without using mode=block. If not specified, most browsers will try sanitizing the page instead of stopping it from loading completely.

### Other Headers
Checks for presence of:
* Content-Security-Policy (this needs some love, as in a full validator. tbd)
* X-Content-Type-Options, also checks if value is set to nosniff
* X-Frame-Options, also checks for ALLOW-FROM directives.
* Referrer-Policy
* Feature-Policy
* Expect-CT

## Installation
```
git clone https://github.com/stfn42/peek.git
```

## Dependencies
_peek_ does currently only support Python 3. It uses the `requests`, `validators`, `tld`, and `urllib3` modules.

The specific versions can be found in the requirements file. The modules can be installed manually or using said file:

Linux/OSX:
```
sudo pip3 install -r requirements.txt
```

Windows:
```
python.exe -m pip install -r requirements.txt
```

## Usage

Usage is generally explained through the `--help` output.

```
peek.py
-------
usage: peek.py [-h] (-t TARGETHOST | -l LISTFILE) [--privacy] [--version]

peek - quick http analysis

optional arguments:
  -h, --help     show this help message and exit
  -t TARGETHOST  target a single host
  -l LISTFILE    import a list of targets from a file
  --privacy      Disables checks against public APIs
  --version      show program's version number and exit

Ping me on Twitter @stfn42 if you get stuck.
```

Some additional things to consider are:
* `-t` expects _one_ target host. If you need more than that, consider using a target file or building a script to call _peek_.
* `-l` will accept a text file with URLs, one per line. They must include schemes (http:// or https://).
* If `--privacy` is not specified, *peek* will look up domains that use the HSTS preload directive using the API provided at hstspreload.com. This argument will also be used in the future to prevent information leakage to other APIs.

## Example
```
 user@host  ~/projects/peek/peek> python peek.py -t https://www.stefanfriedli.ch
peek.py
-------
[+] Started check on https://www.stefanfriedli.ch
[>] HSTS Header: max-age=31536000; includeSubDomains; preload
[*] HSTS: Preload Status:
	[X] Chrome
	[ ] Firefox
	[ ] Tor
[>] X-XSS-Protection Header: 1; mode=block
[>] X-Content-Type-Options Header: nosniff
[>] X-Frame-Options Header: SAMEORIGIN
[-] Security Headers: Content-Security-Policy header is not set.
[>] Referrer-Policy Header: no-referrer-when-downgrade
[>] Feature-Policy Header: accelerometer 'none'; camera 'none'; geolocation 'none'; gyroscope 'none'; magnetometer 'none'; microphone 'none'; payment 'none'; usb 'none'
[-] Security Headers: Expect-CT header is not set.

user@host  ~/projects/peek/peek> python peek.py -t https://www.example.com

[+] Started check on https://www.example.com
[>] HSTS Header: max-age=86400
[-] HSTS: max-age is set to 86400, should be 10368000 or higher.
[-] HSTS: includeSubDomains directive is missing.
[-] HSTS: preload directive is missing.
[>] X-XSS-Protection Header: 1; mode=block
[>] X-Content-Type-Options Header: nosniff
[>] X-Frame-Options Header: SAMEORIGIN
[>] Content-Security-Policy Header: frame-ancestors 'self' *.example.ch
[-] Security Headers: Referrer-Policy header is not set.
[-] Security Headers: Feature-Policy header is not set.
[-] Security Headers: Expect-CT header is not set.

```


## Known issues
* ~~_peek_ does not yet handle invalid SSL certificates gracefully.~~ It does now.

## Shoutouts
* Adam Caudill provides a helpful API to query the inclusion of domains in various HSTS Preload lists. It can be found at https://hstspreload.com/ and is being used within _peek_.
