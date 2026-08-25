# vAnalyzer

> Security plugin for [Vencord](https://vencord.dev/) designed to analyze links, files, and user/server context within Discord.

> We know that Discord has a built-in analyzer, but this expands the possibilities 

![Status](https://img.shields.io/badge/Status-Active-green) ![Language](https://img.shields.io/badge/Language-TypeScript-blue)

---

# How To Install

### src/userplugins folder

> https://docs.vencord.dev/installing/#installing-your-custom-build
> 
> https://docs.vencord.dev/installing/custom-plugins/

### Vesktop Install

> Using [Veskforge](https://github.com/Microck/veskforge)
> <img width="910" height="170" alt="image" src="https://github.com/user-attachments/assets/b198a2a6-a006-4cbc-839b-89ba4b783cd0" />



---

## Quick Summary

vAnalyzer combines three layers:

1. **Manual analysis** from context menus
2. **Automatic analysis** when messages arrive (based on configuration)
3. **Visual enrichment** inside the message (results accessory)
4. **Custom modular scanning system**


Features: whitelists/blacklists, local caching and custom modules to connect your own endpoints.

---

<img width="440" height="214" alt="image" src="https://github.com/user-attachments/assets/badf06e5-6ec2-47d5-9feb-c2d8b6d8ebca" />
<img width="457" height="213" alt="image" src="https://github.com/user-attachments/assets/f6137e24-8232-4c09-bd91-22b0c11401c9" />
Search unknown users
<img width="451" height="138" alt="image" src="https://github.com/user-attachments/assets/96c6c187-2007-4227-bd06-2470d2fd7159" />
<img width="574" height="666" alt="image" src="https://github.com/user-attachments/assets/0df6ef09-06da-412e-8b73-6355ec9d5c9a" />
<img width="620" height="269" alt="image" src="https://github.com/user-attachments/assets/a87b78f6-8fc4-4a12-af94-b756c090d78d" />
<img width="601" height="198" alt="image" src="https://github.com/user-attachments/assets/3f82ae52-6f7a-4836-8646-74cecf9e8491" />
<img width="629" height="358" alt="image" src="https://github.com/user-attachments/assets/caeb8d65-c035-4618-be56-e07794a71cc6" />
<img width="425" height="501" alt="image" src="https://github.com/user-attachments/assets/c9f60a3c-34c0-4368-9273-daa261b3d2cd" />
<img width="626" height="379" alt="image" src="https://github.com/user-attachments/assets/03fb8544-c000-4a73-8bfd-91473f430ad9" />

---

## Main Features

| Feature | Description | Where Used |
| --- | --- | --- |
| Manual context menus | On-demand scanning of URLs, attachments, invites, users | Messages, users, servers |
| Auto-analysis | Automatic analysis when messages arrive | MESSAGE_CREATE flow |
| Link click warning | Alert on flagged domains | Link click interception |
| Message age filter | Ignore old messages by days | Auto-analysis |
| DM-only mode | Limit auto-scan to direct messages | All analyzers |
| Skip friends | Avoid scanning friend messages | Auto-analysis |
| Ignore media files | Skip image/video/audio files | File auto-scan |
| Whitelist/blocklist | Exclude/flag domains | URL pipeline |
| FMHY auto-update | Fetch unsafe sites list | Blocklists |
| OSINT shortcuts | Search User / Search Server | User/server contexts |
| Modular Scan | Custom HTTP endpoints | URL/file analysis |
| Connected members | Public widget member list | Discord invite results |


### Community Scanners & Analyzers

Community-run scanners, each focused on a specific field such as Minecraft files or
Discord user reputation. They are grouped under their own section in the plugin
settings, because every check sends a request to their servers with whatever you look up (file hashes, Discord user IDs, anything you submit): they may log those requests, rate-limit you or be
down entirely.

| Service | Target | What it does | API Key |
| --- | --- | --- | --- |
| [CordCat](https://cord.cat/) | User | Discord sanctions, data breaches and risk scoring | Required |
| [Dangercord](https://status.dangercord.com/) | User | Dangercord blacklist and report counts | Required |
| [Ratter Scanner](https://discord.gg/wEDbPRHyeB) | File | Looks up `.jar` attachments in a database of known malicious and known safe Minecraft files | N/A |
| [UBFB](https://ubfb.theindiebrand.es/) | User | Community-run shared blacklist of scam, raid and dox reports. Can also submit reports | N/A |
| [XN Protect](https://xnprotect.com/) | User | Community global-ban list for Discord | N/A |

### Built-in Analyzers

Always available, not part of the community scanner section.

| Service | Target | What it does | API Key |
| --- | --- | --- | --- |
| CertPL | Domain | Checks the domain against the CERT.PL national phishing blocklist | N/A |
| FishFish | Domain | Community phishing and scam domain database | N/A |
| Sucuri | Domain | Website reputation and malware rating | N/A |
| CrtSh | Domain | Certificate transparency history, exposes newly registered domains | N/A |
| WhereGoes | URL | Traces the full redirect chain to the real destination | N/A |
| [WaybackMachine](https://archive.org) | URL | Looks for an archived snapshot to see what the page used to serve | N/A |
| DiscordInvite | Invite | Resolves the invite: server info, counts, features, widget members | N/A |
| BotProfile | Bot | Inspects a bot account's public profile and status | N/A |
| [VirusTotal](https://www.virustotal.com) | File | Multi-engine scanner verdicts | Partial, hash lookup works without a key, uploading a file needs one |
| [HybridAnalysis](https://hybrid-analysis.com/) | URL/File | Sandbox detonation and multi-scanner verdicts | Required |
| ModularScan | URL/File | Sends the URL or file to your own custom HTTP endpoints | Depends on the endpoint you configure |

### Discord Invite Details

When valid, includes:
- Server ID
- Member/online counts
- Verification level
- Features (Verified, Partnered, etc.)
- NSFW/scam keyword detection
- Public widget members (if enabled, up to 50 listed)

Note: Discord widget API has member listing limits. Plugin applies local cutoff of 50 members.

---

## Without API Key vs With API Key

**Works without any API key:**
- Discord invite analysis
- Domain blocklist checks (CERT.PL, FishFish, Sucuri, crt.sh)
- URL redirect tracing (WhereGoes) and archive snapshots (Wayback Machine)
- Jar file hash lookup (Ratter Scanner)
- User reputation via UBFB and XN Protect
- Bot profile analysis
- Whitelist/blocklist filters
- Search User / Search Server shortcuts, unknown user analyzer
- VirusTotal hash lookup (no upload)
- Modular Scan (if your endpoint allows it)

**Unlocked by an API key:**
- VirusTotal: file upload + report polling
- Hybrid Analysis: URL/file quick scan + result polling
- Dangercord: user reputation lookup
- CordCat: user reputation, sanctions and breach records

---

## Configuration

### API Keys

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| virusTotalApiKey | string | N/A | VirusTotal API key |
| dangecordApiKey | string | N/A | Dangercord API key |
| hybridAnalysisApiKey | string | N/A | Hybrid Analysis API key |
| cordCatApiKey | string | N/A | CordCat API key |

### Protection

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| warnOnLinkClick | bool | true | Alert on flagged link click |
| warnOnFileDownload | bool | true | Flag risky downloads |
| analyzeBotsProfile | bool | false | Auto-analyze bot profiles |
| enableOsintSearchShortcuts | bool | true | Search User / Server shortcuts |
| enableCordCat | bool | true | Show "Analyze with CordCat" |
| enableFindByUserId | bool | true | Show "Find By User Id" |

### Scope

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| skipFriends | bool | true | Skip friend messages |
| autoScanInvitesDirectMessageOnly | bool | false | Invites in DM only |
| autoScanUrlsDirectMessageOnly | bool | false | URLs in DM only |
| autoScanFilesDirectMessageOnly | bool | false | Files in DM only |
| messageAgeFilter | days | 3 | Messages older than X days (0=off) |

### URLs & Invites

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| autoScanInvites | bool | true | Auto-analyze invites |
| autoScanUrls | bool | false | Auto-scan URLs |
| autoScanUrlsCertPL | bool | true | CERT.PL check |
| autoScanUrlsFishFish | bool | true | FishFish check |
| autoScanUrlsWhereGoes | bool | true | Redirect tracing |
| autoScanUrlsSucuri | bool | true | Sucuri reputation |
| autoScanUrlsHybridAnalysis | bool | false | HA URL scan (needs API) |

### Files

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| autoScanFiles | bool | false | Auto-scan files |
| ignoreMediaFiles | bool | true | Skip image/video/audio |
| autoScanFilesVirusTotal | bool | true | VirusTotal scan |
| virusTotalLookupBeforeUpload | bool | true | Hash lookup first |
| autoScanFilesHybridAnalysis | bool | true | HA file scan |

### Filters

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| useBuiltinWhitelist | bool | true | Internal whitelist |
| enableBlocklists | bool | true | Blocklist checking |
| enableFmhyBlocklist | bool | true | FMHY Unsafe list |
| customWhitelist | str | N/A | Custom white domains |
| customBlocklist | str | N/A | Custom black domains |

### Advanced

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| modularScanSettings | UI | N/A | Custom HTTP module editor |

---

## Context Menus and Available Actions

### Message context

| Group | Actions |
| --- | --- |
| User | Scan author reputation (all enabled services, or one per service), Scan author with CordCat, Report author to UBFB |
| Files | Scan file with VirusTotal / Hybrid Analysis / Ratter Scanner (jar) |
| URL | Trace URL (WhereGoes), crt.sh, CERT.PL, FishFish, Sucuri, Hybrid Analysis |
| Invite | Analyze Discord invite |
| Modular | Run custom modules compatible with URL/file |

### User context

| Group | Actions |
| --- | --- |
| Search User | top.gg, DiscordHub |
| Reputation | Scan user reputation (unified), or one entry per enabled service: Dangercord, CordCat, UBFB, XN Protect |
| Analyze | Analyze User with CordCat |
| Report | Report User to UBFB |

### Guild context / guild-header-popout

| Group | Actions |
| --- | --- |
| Search Server | Disboard, DiscordServers, DiscordPlace, Discords |

---

## Modular Scan (Custom Module Configuration)

Each custom module supports:

| Field | Description |
| --- | --- |
| name | Display name |
| type | file or url |
| method | GET, POST, PUT |
| url | Target endpoint |
| headers | Custom headers |
| bodyType | multipart, json, none |
| fileField | File field name in multipart |
| extraFields | Extra multipart fields |
| jsonTemplate | JSON template with placeholders |
| autoScan | Run automatically |
| filter | none, contains, regex |

Supported placeholders:

- {{fileUrl}}
- {{fileName}}
- {{url}}

---

## Built-in Whitelist and Blocklists

Base whitelist includes known domains (Discord, YouTube, GitHub, etc.) to reduce noise and unnecessary queries.

Active blocklists:

1. [FMHY](https://github.com/fmhy/FMHYFilterlist) Unsafe Sites Filterlist
2. User custom list.


## Disclaimer

- I'm not an expert in TypeScript; the plugin has a lot of bugs, and the code is inefficient in many places. I'd love for people to contribute, but always in a respectful way. You might think this project is silly, and I respect that, but I prefer to focus on the positive.

- I am not responsible for any misuse, damages, or consequences arising from the use of this plugin.

## More Images

<img width="599" height="621" alt="image" src="https://github.com/user-attachments/assets/f50acff9-89f2-4011-9d2a-6ec8e8a46bd6" />
<img width="597" height="788" alt="image" src="https://github.com/user-attachments/assets/266c1467-18a0-43b8-9729-7aafe0e7abf3" />
<img width="596" height="791" alt="image" src="https://github.com/user-attachments/assets/5b8fd4d0-70e8-40df-8d54-785e0c32eec1" />
<img width="605" height="796" alt="image" src="https://github.com/user-attachments/assets/5f80c6b0-f23b-4a04-92dc-ea2ecd5b56da" />
<img width="602" height="796" alt="image" src="https://github.com/user-attachments/assets/91a536ec-336e-45ca-a815-66304617bf5f" />
 <img width="597" height="798" alt="image" src="https://github.com/user-attachments/assets/6b9a4e55-0297-40ed-b09a-d872133dde45" />