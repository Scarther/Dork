# 🔎 The Google Dorking Field Manual

> A vast, exploration-first reference for OSINT investigators **and** bug bounty hunters.
> Search operators are a scalpel — this manual teaches you where to cut and, just as importantly, where not to.

---

### Investigator mindset
- **Pivot, don't tunnel.** Every result is a new selector (a username → an email → a phone → a domain).
- **Confirm across sources.** One hit is a lead, not a fact. Corroborate.
- **Preserve the chain.** Screenshot, timestamp, archive (`archive.org`, `archive.ph`) before it disappears.
- **Mind your own OPSEC.** See [Operational Security](#-operational-security-your-own-tracks).

---

## 📖 Table of Contents

1. [Operator Reference](#-operator-reference-the-grammar)
2. [Core Technique Patterns](#-core-technique-patterns)
3. **OSINT Investigation**
   - [Usernames & Handles](#-usernames--handles)
   - [Emails](#-emails)
   - [Phone Numbers](#-phone-numbers)
   - [People, Addresses & Physical Location](#-people-addresses--physical-location)
   - [Vehicles](#-vehicles)
   - [Documents & Files](#-documents--files-osint)
   - [Images, Faces & Geolocation](#-images-faces--geolocation)
   - [Social Media Pivoting](#-social-media-pivoting)
   - [Google Workspace & Cloud Docs](#-google-workspace--cloud-docs-hidden-in-plain-sight)
   - [File-Sharing & Paste Leaks](#-file-sharing--paste-leaks)
   - [Business & Corporate OSINT](#-business--corporate-osint)
   - [Cryptocurrency & Blockchain](#-cryptocurrency--blockchain)
   - [Breach & Leak-Database Awareness](#-breach--leak-database-awareness)
4. **Infrastructure, DNS & Network**
   - [DNS & Domain Intelligence](#-dns--domain-intelligence)
   - [IP & Network Recon](#-ip--network-recon)
   - [Historical & Deleted Endpoints](#-historical--deleted-endpoints)
5. **Bug Bounty & Offensive Recon**
   - [Attack Surface Discovery](#-attack-surface-discovery)
   - [Exposed Credentials & Secrets](#-exposed-credentials--secrets)
   - [Login & Admin Panels](#-login--admin-panels)
   - [Sensitive File Types](#-sensitive-file-types)
   - [Config, Backup & Version Control Leaks](#-config-backup--version-control-leaks)
   - [Error Messages & Info Disclosure](#-error-messages--info-disclosure)
   - [Cloud Buckets & Storage](#-cloud-buckets--storage)
   - [Vulnerability-Indicator Dorks](#-vulnerability-indicator-dorks)
   - [API Keys & Tokens](#-api-keys--tokens)
   - [GitHub Dork Deep-Dive](#-github-dork-deep-dive)
   - [Job-Posting & Tech-Stack Recon](#-job-posting--tech-stack-recon)
   - [IoT, ICS & Network Cameras](#-iot-ics--network-cameras)
6. [Beyond Google — Other Engines](#-beyond-google--other-engines)
7. [Search-Engine Dialects](#-search-engine-dialects-operators-differ)
8. ["My Dork Returns Nothing" Troubleshooter](#-my-dork-returns-nothing--troubleshooter)
9. [The Pivot Map](#-the-pivot-map-how-selectors-chain)
10. [Automation & Tooling](#-automation--tooling)
11. [Operational Security](#-operational-security-your-own-tracks)
12. [Glossary](#-glossary)
13. [Resources & Further Reading](#-resources--further-reading)

---

## 🧱 Operator Reference (the grammar)

Master these and you can build any dork. Combine freely.

| Operator | Does | Example |
|----------|------|---------|
| `"exact phrase"` | Match the literal string | `"internal use only"` |
| `OR` / `\|` | Either term | `login OR signin` |
| `AND` | Both (implicit by default) | `admin AND portal` |
| `-term` | Exclude | `jaguar -car` |
| `*` | Wildcard (one or more words) | `"how to * a lock"` |
| `()` | Group logic | `(sql OR mysql) error` |
| `site:` | Restrict to a domain/TLD | `site:gov.uk` |
| `inurl:` | Term appears in the URL | `inurl:admin` |
| `allinurl:` | All terms in the URL | `allinurl:auth login` |
| `intitle:` | Term in the page `<title>` | `intitle:"index of"` |
| `allintitle:` | All terms in title | `allintitle:login admin` |
| `intext:` | Term in the body | `intext:"password"` |
| `allintext:` | All terms in body | `allintext:username password` |
| `filetype:` / `ext:` | Specific file extension | `filetype:pdf` |
| `cache:` | Google's cached copy | `cache:example.com` |
| `related:` | Sites similar to one | `related:example.com` |
| `link:` | Pages linking to a URL (deprecated, spotty) | `link:example.com` |
| `AROUND(n)` | Two terms within *n* words | `CEO AROUND(3) email` |
| `before:` / `after:` | Date-bounded (`YYYY-MM-DD`) | `after:2024-01-01` |
| `numrange` (`n..m`) | Numeric range | `salary 50000..90000` |
| `location:` | (Google News) by locale | `location:UK` |

**Notes**
- Operators are ANDed by default; `OR` must be UPPERCASE.
- `allin*` operators don't mix well with other operators — use the singular forms when combining.
- Google silently ignores some operators over time; verify behavior, don't assume.
- These same operators (with dialect changes) work on Bing, DuckDuckGo, Yandex — see [Beyond Google](#-beyond-google--other-engines).

---

## 🧩 Core Technique Patterns

Reusable skeletons. Replace `TARGET` / `example.com` and iterate.

**Directory listings (the single most productive dork):**
```
intitle:"index of" TARGET
intitle:"index of /" "parent directory"
```

**Scope a whole org, then subtract the known site to find the shadow surface:**
```
site:example.com -site:www.example.com
```

**Find everything but the marketing pages:**
```
site:example.com -inurl:(login OR signup OR blog OR help)
```

**Selector sweep (great for people):**
```
"SELECTOR" (site:pastebin.com OR site:github.com OR site:trello.com OR site:scribd.com)
```

**Time-boxing a leak or event:**
```
site:example.com "confidential" after:2023-01-01 before:2024-01-01
```

---

# 🕵️ OSINT INVESTIGATION

> Each section below is **exploration-based**: start broad, harvest selectors, pivot. The goal isn't one magic query — it's a chain.

## 👤 Usernames & Handles

A username is the connective tissue of an investigation — the same handle often spans dozens of platforms.

```
"USERNAME"
"USERNAME" (site:twitter.com OR site:x.com OR site:instagram.com OR site:tiktok.com OR site:reddit.com)
"USERNAME" (site:github.com OR site:gitlab.com OR site:stackoverflow.com OR site:keybase.io)
"USERNAME" (site:pastebin.com OR site:ghostbin.com OR site:justpaste.it)
inurl:USERNAME site:linkedin.com
intitle:"USERNAME" profile
"USERNAME" (forum OR profile OR "member since")
```

**Pivot ideas:** a handle on GitHub → commit emails; on a forum → join date & IP-leaking signatures; on gaming sites → linked accounts. Cross-reference with **Sherlock**, **Maigret**, **WhatsMyName** (see tooling).

## 📧 Emails

```
"target@example.com"
"target [at] example.com" OR "target(at)example.com"
"target" "@example.com"
site:example.com intext:"@example.com"        # harvest org email format
"@example.com" (site:pastebin.com OR site:github.com OR site:trello.com)
intext:"target@example.com" (filetype:xlsx OR filetype:csv OR filetype:txt)
```

**Deriving the email format:** find any one employee's email → infer `first.last@`, `flast@`, etc. → generate candidates for others. Verify with **Hunter.io**, **Holehe** (checks which sites an email is registered on), or **have-i-been-pwned** (breach exposure — informational).

## 📱 Phone Numbers

Try every format — indexing is inconsistent.

```
"+1 555 123 4567" OR "555-123-4567" OR "(555) 123-4567" OR "5551234567"
"555.123.4567"
"+15551234567"
intext:"555-123-4567" (site:facebook.com OR site:pastebin.com OR site:classifieds...)
"555-123-4567" (filetype:pdf OR filetype:xlsx OR filetype:csv)
```

**Pivot:** a phone in a classified ad → name + location; in a leak → linked accounts. Cross-check with carrier/lookup services (**Truecaller**, **NumLookup**, **PhoneInfoga** for open-source recon) — respecting local law on phone-tracing.

## 🏠 People, Addresses & Physical Location

> ⚠️ Investigating individuals engages privacy and anti-stalking law. Have a lawful basis. Do not use for harassment.

```
"First Last"
"First Last" "City, ST"
"First Last" (site:linkedin.com OR site:facebook.com OR site:whitepages.com)
"First Last" (filetype:pdf OR filetype:doc) resume OR CV
"123 Main St" "City"
"First Last" "@" ("gmail.com" OR "outlook.com")     # find personal email
intext:"First Last" intext:"555" intext:"@"          # co-occurrence of name+phone+email
site:*.gov "First Last"                                # public records, filings
"First Last" (obituary OR wedding OR "class of")       # relatives & timeline
```

**Public-record pivots:** court dockets, property/assessor sites, business registrations (`site:opencorporates.com`), voter-file mirrors (jurisdiction-dependent). Genealogy and obituary sites reveal family trees and timelines.

## 🚗 Vehicles

```
"VIN" OR "1HGCM82633A004352"                          # a specific VIN string
intext:"VIN" (filetype:pdf OR filetype:xlsx) TARGET
"license plate" "ABC1234"
"ABC1234" (site:facebook.com OR forum OR classifieds)  # plates in photos/listings
site:carfax.com OR site:vehiclehistory.com "VIN"
"for sale" "make model year" "City" intext:"555"       # seller pivot from listing
inurl:vin= OR inurl:plate=
```

**Pivots:** a VIN → history report → prior owners/locations; a plate visible in a social photo → owner's neighborhood; a "for sale" listing → seller's phone/email/name. Dashcam and car-enthusiast forums are goldmines. Combine with **image geolocation** below when you have a photo.

## 📄 Documents & Files (OSINT)

Documents carry **metadata** (author, software, sometimes GPS) — download and inspect with `exiftool`.

```
site:example.com filetype:pdf
"TARGET" filetype:pdf OR filetype:doc OR filetype:docx
"TARGET" filetype:xls OR filetype:xlsx OR filetype:csv
filetype:pdf "internal" OR "confidential" OR "not for distribution"
site:scribd.com "TARGET"
site:slideshare.net "TARGET"
intitle:"index of" (pdf OR doc OR xls) "TARGET"
```

**Metadata pivot:** PDF/Office author field → real name or username → back to [usernames](#-usernames--handles). Presentations and spreadsheets often expose org charts, internal names, and email formats.

## 🖼️ Images, Faces & Geolocation

Google text search seeds; reverse-image engines finish the job.

```
site:flickr.com OR site:instagram.com "TARGET"
"TARGET" imagesize:1920x1080
inurl:jpg OR inurl:png "TARGET"
```

**Then pivot to:** reverse image search (**Google Lens**, **Yandex Images** — best for faces/places, **TinEye** for provenance), **PimEyes** for face matching (respect consent/law). For a photo's *location*: read EXIF GPS with `exiftool`, then match visual cues (signage, architecture, sun angle) — geolocation techniques à la **GeoGuessr** / Bellingcat.

## 🔗 Social Media Pivoting

```
site:twitter.com OR site:x.com "TARGET"
site:reddit.com "TARGET"
site:facebook.com "TARGET"
site:linkedin.com/in "TARGET"
site:t.me "TARGET"                                     # Telegram
site:tiktok.com "@USERNAME"
"TARGET" (site:medium.com OR site:substack.com)        # long-form → beliefs, contacts
```

Each platform leaks different selectors: LinkedIn → employment history + email format, Reddit → interests + timezone from post times, Telegram → group memberships.

## 🗄️ Google Workspace & Cloud Docs (hidden in plain sight)

> The most underrated surface of all. People set a Doc / Sheet / Drive folder to **"anyone with the link"** believing that's private — Google indexes those links anyway. Gmail *inboxes* are **not** indexable, but Google Groups exposes the same email threads and addresses.

```
site:docs.google.com "TARGET"                            # public Docs / Sheets / Slides
site:docs.google.com/spreadsheets "TARGET"               # Sheets only — raw data, rosters, PII
site:drive.google.com "TARGET"                           # shared Drive files & folders
site:groups.google.com "TARGET"                          # internal email threads + addresses
site:google.com/maps/d "TARGET"                          # custom "My Maps" — home addresses, routes
inurl:forms.gle OR inurl:docs.google.com/forms "TARGET"  # Forms (sometimes exposed responses)
site:sites.google.com OR site:script.google.com "TARGET" # Sites & Apps Script projects
```

**Why it works:** `site:docs.google.com` scopes to Google's own document host; adding a path segment like `/spreadsheets` narrows the file type. Sheets are the jackpot — budgets, member lists, mailing lists. **Pivot:** a name in a shared Doc → [email format](#-emails); a My Map → a home address; a Group thread → the whole distribution list.

## 📤 File-Sharing & Paste Leaks

Beyond Google's own storage, the other consumer clouds and collab tools people accidentally make public.

```
(site:dropbox.com OR site:onedrive.live.com OR site:1drv.ms OR site:box.com OR site:mega.nz OR site:we.tl) "TARGET"
(site:pastebin.com OR site:ghostbin.com OR site:gist.github.com OR site:justpaste.it OR site:controlc.com) "TARGET"
(site:trello.com OR site:notion.so OR site:airtable.com OR site:padlet.com) "TARGET"   # public boards / wikis
(inurl:atlassian.net OR site:*.atlassian.net) "TARGET"                                  # Jira / Confluence
```

**Pivot:** Trello cards leak credentials in descriptions; paste sites hold config dumps and breach snippets. Cross-reference with **Intelligence X** and **grep.app**.

## 🏢 Business & Corporate OSINT

```
"COMPANY" site:opencorporates.com                        # registration, directors, filings
"COMPANY" (site:sec.gov OR site:efts.sec.gov)            # EDGAR — US public-company filings
"COMPANY" filetype:pdf ("annual report" OR "10-K" OR prospectus)
"COMPANY" (inurl:courtlistener.com OR inurl:pacer)       # US court dockets
"COMPANY" ("org chart" OR "board of directors") filetype:pdf
site:linkedin.com/company "COMPANY"                      # employees → email format, tech stack
```

**Pivot:** filings name officers → [people](#-people-addresses--physical-location); org charts leak the internal structure and email format.

## 🪙 Cryptocurrency & Blockchain

```
"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"                     # a specific BTC address string
"0xABC...123" (site:etherscan.io OR site:bscscan.com)    # ETH / BSC address on explorers
"WALLET" (site:reddit.com OR site:bitcointalk.org OR forum)  # address tied to a handle
"WALLET" (site:pastebin.com OR site:github.com)
```

**Pivot:** a wallet posted next to a username on a forum links an on-chain identity to a person — then trace flows with blockchain explorers and clustering tools (beyond dorking itself).

## 🔓 Breach & Leak-Database Awareness

> ⚠️ **Legal line:** checking *whether* an account appears in a breach (exposure awareness) is worlds apart from downloading or using breached credentials. The first is standard defensive OSINT; the second is trafficking in stolen data. Stay on the awareness side.

- **Have I Been Pwned** — is this email / phone in a known breach? (informational, defensible)
- **DeHashed / Intelligence X / Snusbase** — powerful, commercial; know your jurisdiction and their terms.
- **Dorking angle:** leaked datasets surface on paste sites — `"@example.com" (password OR dump OR combolist) site:pastebin.com`. If you find your target's data, **report it**; do not harvest.

---

# 🌐 INFRASTRUCTURE, DNS & NETWORK RECON

> Serves both sides: OSINT (who owns this, what's connected) and bug bounty (map the attack surface). **Google can't resolve DNS live** — it indexes the *leaks*; dedicated engines do the resolving.

## 🌍 DNS & Domain Intelligence

```
# Google side — indexed leaks
intitle:"index of" ("zone" OR "named.conf" OR "db.example.com")   # BIND zone files
"AXFR" "example.com"                                     # zone-transfer output pasted online
filetype:conf (named OR bind OR resolv) "example.com"    # DNS server configs
site:*.example.com -www                                  # indexed subdomains

# Dedicated engines — these do the actual resolving
crt.sh          → every subdomain ever issued a TLS cert   (highest-yield)
urlscan.io      → hostnames / URLs seen in the wild
VirusTotal      → resolutions, sibling domains, subdomains
SecurityTrails / DNSDumpster → passive DNS history
ViewDNS         → reverse-IP, WHOIS history, DNS records
```

**Why CT logs win:** every HTTPS cert is publicly logged, so **crt.sh** reveals subdomains that never appear in the web crawl — including internal-sounding ones (`vpn.`, `jira.`, `dev.`). Single highest-yield subdomain source, and most newbies have never heard of it.

## 📶 IP & Network Recon

```
# Reverse-IP / shared hosting
Bing:     ip:203.0.113.10                                # co-hosted domains (Bing-only operator!)
ViewDNS:  reverse-IP lookup                              # other sites on the same host

# Service & banner view
Shodan:   ip:203.0.113.10                                # open ports / services on the IP
Shodan:   asn:AS15169                                    # every host in an ASN
Shodan:   org:"Example Inc"                              # assets by org name
Censys:   <IP or domain>                                 # certs, services, history

# IP in the wild
"203.0.113.10" (filetype:log OR site:pastebin.com)       # IP appearing in logs / pastes
```

**Pivot:** reverse-IP finds virtual hosts sharing one server (often expands bug-bounty scope); ASN sweeps map an org's whole netblock.

## 🕰️ Historical & Deleted Endpoints

Removed pages, old parameters and long-deleted secrets survive in archives — an underrated way to find endpoints gone from the live crawl.

```
Wayback:  http://web.archive.org/web/*/example.com/*     # every archived path
urlscan:  example.com                                    # historical URLs with parameters
site:web.archive.org example.com                         # archive pages Google itself indexed
gau / waybackurls example.com                            # CLI: pull all known URLs (tooling)
```

**Why:** a dev deletes a leaky endpoint but the archive keeps it — old API paths, retired admin pages, secrets in since-scrubbed JavaScript.

---

# 🐛 BUG BOUNTY & OFFENSIVE RECON

> ✅ **Scope discipline:** run these only against domains explicitly in your authorized program scope. Finding an exposed secret is fine; using it is not. Report through the program.

## 🌐 Attack Surface Discovery

Map everything the target has published.

```
site:example.com
site:example.com -www                                  # non-www hosts
site:*.example.com                                     # subdomains (spotty; use amass/subfinder too)
site:example.com inurl:api
site:example.com inurl:dev OR inurl:staging OR inurl:test OR inurl:uat
site:example.com inurl:old OR inurl:beta OR inurl:legacy
site:example.com (inurl:php OR inurl:asp OR inurl:jsp)  # tech fingerprint
site:example.com ext:php inurl:?                        # parameterized endpoints (injection surface)
```

## 🔑 Exposed Credentials & Secrets

The highest-signal, highest-sensitivity category. **Report, never reuse.**

```
site:example.com (intext:"password" OR intext:"passwd" OR intext:"pwd")
intext:"password" filetype:log
filetype:env "DB_PASSWORD"
filetype:env "APP_KEY" OR "SECRET"
"BEGIN RSA PRIVATE KEY" filetype:key OR filetype:pem
site:pastebin.com "example.com" password
intitle:"index of" ".ssh"
intitle:"index of" id_rsa
filetype:sql "INSERT INTO users" ("password" OR "pass")
filetype:xls OR filetype:csv intext:password
```

## 🚪 Login & Admin Panels

```
site:example.com (inurl:login OR inurl:signin OR inurl:admin OR inurl:auth)
intitle:"login" site:example.com
inurl:admin intitle:"login"
inurl:/wp-admin OR inurl:/wp-login.php site:example.com
inurl:/administrator site:example.com                  # Joomla
inurl::8080 OR inurl::8443 site:example.com            # non-standard ports
intitle:"phpMyAdmin" "Welcome to phpMyAdmin"
intitle:"Dashboard" inurl:admin
inurl:/manager/html                                    # Tomcat
```

## 🗂️ Sensitive File Types

```
site:example.com filetype:log
site:example.com filetype:sql
site:example.com filetype:bak OR filetype:old OR filetype:backup
site:example.com filetype:env
site:example.com filetype:config OR filetype:conf OR filetype:cfg
site:example.com filetype:ini
site:example.com filetype:yml OR filetype:yaml
site:example.com filetype:json intext:"api"
site:example.com ext:txt inurl:robots                  # robots.txt → hidden paths
filetype:xml inurl:sitemap site:example.com
```

## ⚙️ Config, Backup & Version Control Leaks

```
inurl:.git site:example.com
intitle:"index of" ".git" site:example.com
inurl:".git/config"
inurl:".svn/entries"
inurl:.DS_Store site:example.com
filetype:bak inurl:php site:example.com
inurl:wp-config.php.bak OR inurl:wp-config.php~
intitle:"index of" "web.config"
filetype:conf inurl:nginx OR inurl:apache
"index of" "docker-compose.yml"
```

## 💥 Error Messages & Info Disclosure

Leaked stack traces reveal stack, paths, and versions.

```
intext:"Warning: mysql_" site:example.com
intext:"Fatal error" intext:"on line" site:example.com
intext:"Whoops, looks like something went wrong" site:example.com   # Laravel debug
intext:"Traceback (most recent call last)" site:example.com          # Python
intext:"Microsoft OLE DB Provider for SQL Server error"
intitle:"phpinfo()" OR intext:"PHP Version"
intext:"SQL syntax" intext:"error"
"Index of /" "server at" site:example.com
```

## ☁️ Cloud Buckets & Storage

```
site:s3.amazonaws.com "example"
site:storage.googleapis.com "example"
site:blob.core.windows.net "example"                   # Azure
site:digitaloceanspaces.com "example"
intitle:"index of" site:s3.amazonaws.com
inurl:s3.amazonaws.com filetype:xls OR filetype:pdf
```

## 🎯 Vulnerability-Indicator Dorks

Parameterized URLs hinting at classic bug classes (**verify manually, in scope, safely**).

```
site:example.com inurl:"id=" ext:php                   # potential SQLi/IDOR
site:example.com inurl:"redirect=" OR inurl:"url=" OR inurl:"next="   # open redirect / SSRF
site:example.com inurl:"file=" OR inurl:"path=" OR inurl:"page="      # LFI/path traversal
site:example.com inurl:"q=" OR inurl:"search=" OR inurl:"query="      # reflected XSS
site:example.com inurl:"debug=true" OR inurl:"test=1"
site:example.com inurl:"callback=" OR inurl:"jsonp="                  # JSONP/CORS
inurl:"/proxy?url=" site:example.com                                  # SSRF
```

## 🔐 API Keys & Tokens

```
site:example.com intext:"api_key" OR intext:"apikey" OR intext:"api-key"
"AIza" site:example.com                                 # Google API key prefix
"AKIA" filetype:env OR filetype:log                     # AWS access key ID prefix
intext:"xoxb-" OR intext:"xoxp-"                        # Slack tokens
intext:"ghp_" OR intext:"github_pat_"                   # GitHub PAT
filetype:json "private_key" "client_email"             # GCP service account
"sk_live_" filetype:log OR filetype:txt                 # Stripe live key
```

> GitHub-hosted secrets are better hunted with **TruffleHog**, **gitleaks**, and GitHub code search — see the deep-dive below.

## 🐙 GitHub Dork Deep-Dive

GitHub code search has **its own operator dialect** — far more powerful than `site:github.com` on Google. Search at github.com/search (Code tab), or the API.

```
org:TARGET                                               # scope to an organization
org:TARGET filename:.env                                 # env files in the org's repos
org:TARGET filename:config path:/                        # config at repo root
"TARGET.com" language:yaml                               # domain hardcoded in YAML
"api_key" OR "apikey" org:TARGET
extension:pem OR extension:key                           # private keys
filename:.npmrc _auth                                    # npm auth tokens
filename:.git-credentials
"BEGIN RSA PRIVATE KEY"
path:.github/workflows "secrets."                        # CI secret usage
```

**Operator crib:** `org:`, `user:`, `repo:`, `filename:`, `path:`, `extension:`, `language:`. **Better tools:** run **TruffleHog** / **gitleaks** against the org — they scan *git history*, catching secrets that were committed then deleted (still recoverable). And check individual developers' **personal repos and gists** — secrets leak there far more than in official org repos.

## 💼 Job-Posting & Tech-Stack Recon

Job ads are a **free internal-tech disclosure** — and badly underused.

```
"TARGET" (site:linkedin.com/jobs OR site:indeed.com OR site:greenhouse.io OR site:lever.co)
"TARGET" jobs ("we use" OR "experience with") (Kubernetes OR Splunk OR Okta OR SAP)
site:stackshare.io "TARGET"                              # declared tech stack
"TARGET" ("powered by" OR "built with") filetype:pdf
```

**Why it's gold:** a posting demanding "5 years Palo Alto + CrowdStrike + Jenkins" hands you the exact security stack, CI system, internal tool names, and often a hiring-manager email — recon that'd otherwise cost days.

## 📷 IoT, ICS & Network Cameras

> ⚠️ Viewing a live camera or control-system UI you don't own can be unauthorized access **even if it's unauthenticated**. Enumerate for awareness / reporting; do not interact.

```
# Google
intitle:"Live View / - AXIS"                             # Axis network cameras
inurl:"/view/view.shtml"                                 # generic IP camera
intitle:"webcamXP 5"
inurl:":8080" intitle:"Network Camera"

# Shodan (far better for this)
Shodan:  webcam
Shodan:  port:554 has_screenshot:true                    # RTSP streams
Shodan:  "Modbus" port:502                               # ICS / SCADA — report, never touch
```

---

## 🌍 Beyond Google — Other Engines

Google is one index. Diversify; each finds what others miss.

| Engine | Strength |
|--------|----------|
| **Bing** | Similar operators; different crawl; `ip:` operator for reverse-IP |
| **DuckDuckGo** | Bang shortcuts (`!g`, `!s3`); less personalization |
| **Yandex** | Best-in-class reverse image / face search; strong on non-Western content |
| **Baidu** | Chinese-language surface |
| **Shodan** | Internet-connected devices/services (`org:`, `port:`, `ssl.cert.subject.cn:`) |
| **Censys** | Certificates, hosts, exposed services |
| **FOFA / ZoomEye** | Asset & banner search, favicon hashing |
| **GreyNoise** | Context on scanning/background-noise IPs |
| **crt.sh** | Certificate Transparency → subdomain enumeration |
| **Wayback Machine / archive.ph** | Historical & deleted pages, old params, removed secrets |
| **Intelligence X** | Leaks, pastes, darkweb selectors |
| **grep.app / GitHub search** | Source-code-level secret hunting |

**Shodan starter dorks:**
```
org:"Example Inc"
ssl.cert.subject.cn:"example.com"
http.favicon.hash:-123456789
port:9200 product:"Elastic"            # exposed Elasticsearch
"default password"
```

---

## 🗣️ Search-Engine Dialects (operators differ!)

Same idea, different syntax per engine — one of the biggest silent time-sinks for newbies. A dork that works on Google may return nothing on Bing not because the data isn't there, but because the *operator* changed.

| Capability | Google | Bing | DuckDuckGo | Yandex |
|---|---|---|---|---|
| Site restrict | `site:` | `site:` | `site:` | `site:` / `host:` |
| Title match | `intitle:` | ⚠️ limited | `intitle:` | `intitle:` |
| URL match | `inurl:` | `inurl:` (weak) | `inurl:` | `inurl:` |
| Filetype | `filetype:` / `ext:` | `filetype:` / `ext:` | `filetype:` | `mime:` |
| Reverse-IP | ❌ | **`ip:` ✅** | ❌ | ❌ |
| Wildcard word `*` | ✅ | ⚠️ limited | ⚠️ limited | **✅ strong** |
| Regex-ish matching | ❌ | ❌ | ❌ | **✅ (best)** |
| Bang shortcuts | ❌ | ❌ | **`!g !s3 !gh` ✅** | ❌ |

**Which engine, when — the newbie cheat-sheet:**
- **Google** — default; richest operator set and biggest index.
- **Bing** — the *only* mainstream engine with reverse-IP (`ip:`); often keeps pages Google dropped. Always run your key dorks here too.
- **DuckDuckGo** — no result personalization + **bangs**: `!shodan example.com`, `!github org:acme`, `!wayback example.com` jump straight into another tool.
- **Yandex** — strongest wildcards and (via Images) the best face/place reverse-image search; superior on non-Latin content.
- **Baidu** — Chinese-language surface Google barely touches.

> **Habit to build:** never trust a single engine's "no results." Run the same dork on Google + Bing + Yandex before concluding something isn't out there.

## 🧯 "My Dork Returns Nothing" — Troubleshooter

| Symptom | Likely cause | Fix |
|---|---|---|
| Zero results | Too many ANDed terms | Drop terms one at a time; widen the net |
| Operator seems ignored | Google deprecated/limited it (`link:`, `cache:`, `+`) | Use an alternative or a dedicated engine |
| CAPTCHA / "unusual traffic" | Too many fast queries | Slow down, rotate, prove you're human |
| `allintitle:` / `allintext:` acting odd | They don't combine with other operators | Switch to singular `intitle:` / `intext:` |
| Right site, irrelevant pages | Missing quotes | Wrap exact phrases in `"..."` |
| Stale or removed page | It was deleted | Try `cache:`, Wayback, urlscan |
| Works on Google, empty on Bing | Different operator dialect | Check the table above |

## 🧭 The Pivot Map (how selectors chain)

The craft isn't one query — it's turning each result into the *next* selector.

```
             ┌──────────┐
             │ USERNAME │──► GitHub ──► commit EMAIL
             └────┬─────┘                   │
                  │                         ▼
             social profiles         org email FORMAT
                  │                         │
                  ▼                         ▼
    NAME ◄──────────────────────────────► EMAIL ──► breach exposure
     │                                      │
     ▼                                      ▼
   PHONE ──► classified ad ──► ADDRESS   documents ──► exiftool ──► real NAME
     │                           │
     ▼                           ▼
 messaging apps            property records ──► relatives
```

> **Rule:** never stop at one hit. Every selector you confirm should spawn at least two new searches.

---

## 🤖 Automation & Tooling

Manual dorking teaches intuition; tools give scale. (Install per your workflow.)

**Dorking / recon automation**
- `googler`, `ddgr` — CLI search
- **theHarvester** — emails, subdomains, hosts from many sources
- **Photon** / **gau** / **waybackurls** — crawl & pull historical URLs
- **dorkscout**, **fast-google-dorks-scan**, **Dorks Eye** — dork runners
- **GHDB (Google Hacking Database)** at exploit-db.com/google-hacking-database — thousands of vetted dorks

**Person/selector OSINT**
- **Sherlock**, **Maigret**, **WhatsMyName** — username across platforms
- **Holehe** — which sites an email is registered on
- **PhoneInfoga** — phone recon
- **SpiderFoot**, **Recon-ng**, **Maltego** — full automation graphs
- **exiftool** — file/image metadata

**Secret hunting (bug bounty)**
- **TruffleHog**, **gitleaks** — secrets in git history
- **subfinder**, **amass** — subdomain enumeration
- **nuclei** — templated vuln scanning of discovered surface

**DNS / IP / infrastructure**
- **crt.sh**, **DNSDumpster**, **SecurityTrails** — subdomains & passive DNS
- **ViewDNS**, **urlscan.io**, **VirusTotal** — reverse-IP, WHOIS, resolutions
- **Shodan**, **Censys**, **FOFA**, **ZoomEye** — service/banner search
- **dnsx**, **dnsrecon**, **massdns** — CLI resolution at scale

> Tooling automates the *finding*. Judgment — scope, legality, reporting — stays human.

---

## 🥷 Operational Security (your own tracks)

Investigating leaves traces too.

- **Never log into / interact with** accounts, panels, or data you discover. Passive read only.
- Use a **research browser profile** (or VM/container) separate from personal identity.
- Consider a **VPN** and clean, non-attributable accounts for sensitive investigations.
- Google may **rate-limit or CAPTCHA** heavy dorking — slow down; automation that hammers looks like abuse.
- **Don't tip off the target**: avoid clicking through to their live login pages from an attributable IP if stealth matters.
- **Archive before you act** — pages vanish once someone notices exposure.
- Keep an **audit log** of queries, timestamps, and sources for report credibility and legal defensibility.

### 🎯 Scope discipline (bug bounty)
- Before you start, **write down the in-scope domains/IPs** from the program brief and keep them visible.
- When a dork surfaces a host, check it against that list *before* probing — `site:*.example.com` and reverse-IP will happily pull in **out-of-scope** assets (partners, acquisitions, shared hosting).
- Out-of-scope ≠ fair game. Testing it can void your reward and cross a legal line.
- Keep in-scope and out-of-scope findings in **separate notes** so nothing leaks into a report by accident.

---

## 📖 Glossary

- **Dork / Google dork** — a search query using advanced operators to surface specific, often unintended, content.
- **Selector** — any pivotable identifier: name, username, email, phone, IP, wallet, VIN.
- **Attack surface** — everything about a target reachable or observable from outside.
- **CT log (Certificate Transparency)** — public logs of every TLS certificate issued; a subdomain goldmine.
- **Passive DNS** — historical record of what a domain resolved to over time.
- **Reverse-IP** — finding all the domains hosted on a single IP address.
- **ASN (Autonomous System Number)** — an organization's registered block of IP networks.
- **Pivot** — using one finding to seed the next search.
- **Dialect** — an engine's particular operator syntax (Google ≠ Bing ≠ Yandex).
- **OPSEC** — protecting your own operational tracks while investigating.

---

## 📚 Resources & Further Reading

- **Google Hacking Database (GHDB)** — exploit-db.com/google-hacking-database
- **OSINT Framework** — osintframework.com (visual selector→tool map)
- **Bellingcat's Online Investigation Toolkit**
- **IntelTechniques** (Michael Bazzell) — books & tools for people OSINT
- **Bug bounty platforms** — HackerOne, Bugcrowd, Intigriti (always read program scope first)
- **PortSwigger Web Security Academy** — turn a dork find into a validated finding, legally

---

### 🧭 Practice Path (for the class)

1. **Pick a consenting target** — your own name, your own domain, or a deliberately-vulnerable lab (e.g., a CTF or your own test site).
2. **Selector chain drill:** start from one username, reach an email, a phone, and a document — diagram the pivots against [the Pivot Map](#-the-pivot-map-how-selectors-chain).
3. **Surface map drill:** `site:` your own domain, catalog every file type and subdomain Google knows — then compare against **crt.sh** and note what CT logs found that Google missed.
4. **Engine-dialect drill:** run one identical dork on Google, Bing, and Yandex; record where results differ and why (see the [dialect table](#-search-engine-dialects-operators-differ)).
5. **Report drill:** write up one "finding" as if submitting to a bounty program — impact, reproduction, remediation — and check it against the [scope discipline](#-scope-discipline-bug-bounty) checklist first.

> The operators are easy. The craft is knowing which thread to pull, corroborating it, and staying on the right side of the law while you do.

---

*Manual for education and authorized testing. You are responsible for how you use it.*
