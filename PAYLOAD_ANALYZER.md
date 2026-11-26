# Offline evidence pipeline 1.1.1

Python 3.10+, standard library only. No network, model service or payload execution.

## Error-channel extraction (1.9.1)

Value-returning subqueries submitted inside error functions are classified as data extraction / inference and exploitation attempts, including dictionary and schema reads. Constant-only errors remain probes; boolean-blind checks retain their existing classification. Campaign evolution lists the submitted error function, full verbatim subquery, referenced tables/views and row selectors with first-seen time, request count and statuses. Focus mode filters these entries; the executive summary counts the payloads. These descriptions do not establish successful extraction or impact.

## Injected section (1.9.2)

Campaign examples and entry details retain their payload and add an untruncated, evidence-based Injected section when different from the whole value. JSON leaves include their key paths; deeper decoding layers are labelled. Error-based sections and the Error expression column retain complete balanced error calls alongside submitted subqueries. These excerpts make no claim about success or impact. Sections are computed once per displayed attack unit.

## Database code execution and expression error channels (1.9.3)

SQL phases distinguish probing (syntax, boolean, timing and capability checks, e.g. `1=1`), enumeration (structure, environment, row counts and value sizes, e.g. `SELECT COUNT(PASSWORDHASH) FROM APP.T`) and extraction (stored application values, e.g. `SELECT EMAIL FROM APP.T`). This applies across error, direct and blind channels. Nonconstant error-channel arguments appear as Submitted expression with a Kind column. Enumeration uses the metadata lane; extraction uses the data extraction / inference lane. Database-hosted Java execution, executable scheduler jobs and Java-extension XSLT use the command-execution lane: bare capability checks remain probes and supplied actions are exploitation attempts. Plain XSLT without extension namespaces remains SQL injection enumeration. JSON-leaf excerpts suppress ancestor and bracket-only duplicates. Classification does not establish execution or impact.

## Recommended pipeline

```
python -I payload_analyzer.py pipeline ..\incident.json -o ..\payload_analysis.json
```

Plain output contains decoded payloads; `.pax` keeps them obfuscated.
Both modes also write a `.determined` report before the extension chain, containing analysed SQLi/RCE/file-access units and keyword/path probes from determined series. Use `--determined-output PATH` to override it or `--no-determined-output` to disable it.

Pipeline includes unchanged baseline parameters by default so series and exclusion counts cover all traffic; `--assessor-matched-only` restores the former matched-only input. Direct resolved-input mode is unchanged.

Pipeline options: `--keep-resolutions PATH`, `--xor-key-hex HEX`, `--decode-depth N` (1â€“8, default 4), and `--exclude-not-attack`. Resolutions use a temporary `.pax` in the output folder, removed even on failure; an optional retained copy follows PATH's extension. Existing direct usage remains `python -I payload_analyzer.py RESOLUTIONS -o OUT`. Occurrences include URL-decoded `dec_value`; units include `final_decoded_value` from the longest decoding chain (lowest node ID breaks ties).

Both stages support plain JSON/JSONL, `.gz` and `.pax`. `paxio.py pack IN OUT` and `unpack IN OUT` preserve decoded input bytes, including a byte-order marker and line endings. `cat IN` prints decoded text without a plain intermediate. Atomic output temporaries use the final container format. Gzip output has a fixed timestamp and empty filename.

The keyed format is `PAX1`, version byte 1, then deterministic gzip bytes transformed using a repeating XOR key. The default is a fixed 32-byte application key. Override it consistently across stages using `--xor-key-hex HEX` or `PAX_KEY_HEX`; the CLI option wins. Keys must be nonempty hexadecimal byte strings, up to 4096 bytes.

**This is obfuscation, not encryption or authentication.** A checksum detects accidental compressed-stream corruption, not tampering. Coincidental byte sequences remain possible. Decoded evidence must stay in an approved location, and report values must be rendered as escaped text.

## Analyzer contract

All units are included by default; `--exclude-not-attack` omits benign units. Stable units retain source occurrences and decoding nodes. Every technique/step cites an exact node substring, and every artifact must literally occur in a source node; runtime validation rejects unverifiable claims. Source literals remain verbatim without changing the neutral prose templates. Description-only derivations are recomputed and are not promoted to evidence or artifacts.

Per-unit errors retain nodes/occurrences with null `analysis`, `analysis_status: error`, and `analysis_error`; inspect stderr and `meta.errors_total` even when the CLI exits zero. Other units continue. Error units count as undetermined. `meta.source_sha256` hashes decoded input bytes; `source_container_sha256` additionally hashes stored bytes when different. Output is deterministic for identical input/path/options except `generated_at`. JSONL streams in, while JSON arrays and the deduplicated report remain in memory.

The workspace assessor preserves the reference extraction/decoding logic with shared container I/O. Encoded catalogues are Base64-of-compressed JSON, decoded as data, never executed. The finite signature-token source scan covers every `.py` and `.md`; **actual corporate endpoint acceptance has not been tested or guaranteed**. No security exclusions or settings are changed.

## Differential series analysis (analyzer 1.4.0, catalogue 1.3.0)

The third determined category, `file_access`, covers whole OS canary paths, repeated parent-directory traversal, remote UNC paths and source-reading inclusion wrappers. Bare non-canary local paths are not determined alone. Code-interpreting inclusion wrappers remain RCE; log/environment paths alone remain file access. Purpose priority is RCE, file access, SQLi techniques, then supporting techniques.
In a series containing determined file access, other filesystem-path values become `path_probe` members with `determined_via: series` and a neutral series description; summaries count these probes and families include their role.

Occurrences are scoped by site, URI path and parameter name; source IP overlap is recorded, not required.
JSON series share a structure and fixed leaves, with at most two varying paths and three distinct values.
The deepest JSON-parsing decoding node supplies decoded leaves, preserving quoted characters.
Text series contain all non-JSON values in a scope, with at least three distinct values (no similarity threshold).
Their varying segment lies between common prefix/suffix boundaries snapped to complete tokens; empty edges mean whole value.
Synthetic extraction nodes retain parent IDs and routes; normal rules and substring evidence validation run again.
Python expression and timing probes are distinguished from unqualified database delay calls.
Determined series identify determined members, catalogue keyword probes and other variants; benign series are not promoted.
The determined report includes determined members, keyword probes and path probes only; other variants remain in the series member list.
Top-level series include stable IDs, chronology, IP union/overlap, counts, families, members and neutral summaries.
Determined metadata counts excluded units and requests, treating missing request counts as zero.

## Sanitizing reports (analyzer 1.6.0)

```
python -I payload_analyzer.py sanitize INPUT -o OUTPUT [--only-series] [--mapping PATH]
```

Reads full or determined `.json`/`.json.pax` reports; OUTPUT may be plain `.json` or `.pax`.
Only these are replaced, with consistent numbered pseudonyms; all other text is untouched:

- IPv4 -> `198.18.x.y`, IPv6 -> `2001:db8::N`, emails -> `userN@example.invalid`
- domains (letter TLD, not a common file extension) and URL hosts -> `hostN.invalid`
- target sites -> host pseudonyms; target URI paths (2+ chars) -> `/pathN` wherever the
  whole path appears; other URL and Unix paths stay readable
- Windows and UNC paths: the UNC server -> `hostN`, each segment -> `segN` (extension kept),
  except OS folders, file-access canaries, `..` and 1-character segments
- a UNC/site server name learned anywhere is also replaced where it appears as a bare word

Percent-encoded strings are decoded, sanitized and re-encoded (only if something changed).
Loopback/unspecified addresses, `localhost`, `.invalid`/`.example`/`.test` and the public
hosts `w3.org`, `schemas.microsoft.com`, `schemas.xmlsoap.org`, `google.com`,
`microsoft.com`, `github.com` are kept. IDs, hashes, rule IDs, categories, versions,
timestamps and statuses are never rewritten.
`--only-series` retains meta, series and only member units. `--mapping PATH` writes a
separate entity-original-to-replacement table for local use only: never share it with
the sanitized report. Review the output before sharing; pseudonymisation is best-effort.
Replacement counts and written paths appear on stderr.

Keyword probes expose the most frequent determined category; RCE > file access > SQLi > XSS breaks ties only. Catalogue families require support from at least 5% of determined members (each member counts once per family); minority matches below that threshold neither list a family nor enable path promotion. Plain path probes require substantial file-access support and always promote only to `file_access`, never RCE. Simple alphanumeric identifiers separated by `/`, `-`, `_`, `.`, or `:` do not trigger the unmatched suspicious-syntax heuristic; keyword and catalogue checks still apply.
Promoted members retain `own_category`. Units expose `effective_category` without changing rule-based
`analysis`; metadata adds `effective_category_counts` alongside rule-based category counts.

## Sanitizing the raw input (analyzer 1.8.0)

```
python -I payload_analyzer.py sanitize-input INPUT.json -o shareable_input.json --mapping mapping.json
```

Pseudonymises the raw JSONL export (the pipeline input) with the same rules as `sanitize`. Only the fields the
pipeline reads are kept (site, uri_path, uri_query, src, count, et, lt, status, action). Sites, URI paths and
source IPs are replaced; in query names/values only the IPs, hosts, emails and paths change, and every other
character keeps its exact encoding. Whole-value Base64 layers are decoded, rewritten and re-encoded. Afterwards
every query is decoded again as the assessor does; lines that still decode to a replaceable value are listed
in a WARNING (review or remove them before sharing). Keep `mapping.json` local.

Analyzer 1.8.1: Base64 layers that are raw-DEFLATE compressed (for example SAML redirect-binding
`SAMLRequest` values) are inflated, pseudonymised and re-compressed, and the final check inflates them too.
Inputs sanitized with 1.8.0 can still contain original host names inside such values: re-run
`sanitize-input` with 1.8.1 before sharing. Opaque single-sign-on protocol values (SAML messages, signatures,
session/state tokens) are classified as `not_attack` instead of being decoded into accidental SQL/RCE text.

## Catalogue 1.4.0 (analyzer 1.7.0)

Adds bare conditional SQL subqueries, Oracle dictionary queries, standalone SELECT queries and quoted comment truncation; arithmetic template-expression probes; local file-scheme URLs; and XSS script elements, event-handler attributes, JavaScript URIs and attribute-boundary markup. Ordinary sort values, prose and variable-only template placeholders do not establish an attack. Python timing detection requires a qualified call; JavaScript tagged-template syntax is not a PHP command. Category priority is RCE > file access > SQLi > XSS.

## Catalogue 1.4.1 (analyzer 1.8.0)

Adds balanced scalar subqueries and conditional inference probes, database context and dynamic SQL APIs, Derby query exports, SQL modification/output clauses, database file/network APIs, shell timing probes and additional sensitive traversal forms. Native CQL/JQL searches, ordinary filters and non-canary document paths are not attacks by themselves. URL path suffixes are not SQL division; JSP namespace attributes are not HTML attribute injection.

The new `ssrf` category covers HTTP(S) URLs explicitly targeting loopback, private, link-local or internal-name destinations. It describes a request probe, not observed server-side retrieval. Cloud metadata endpoints and file-scheme URLs remain `file_access`. Category priority is RCE > file access > SQLi > XSS > SSRF. Sanitized host/IP pseudonyms cannot establish the original destination's network scope.

A sanitized production report was reanalysed against the previous catalogue: 699 rule-based category changes, including 647 newly determined units, 27 determined-category corrections and 25 removed false SQL-arithmetic determinations in service URLs. Nine sanitized parent/leaf inconsistencies failed validation identically before and after; series-effective categories were not remeasured. Rule precision review sampled up to ten units per observed rule, not every determination.

### Additional request and expression coverage

The encoded catalogue also recognises explicit HTTP request definitions, database connection URLs,
remote XML-parser source directives (including a percent-encoded form), internal-resource URLs with
additional fetch schemes, Windows transfer-command chains, database address lookups and literal-only
function comparisons. HTML elements that embed remote resources are XSS probes. These classifications
describe supplied syntax, not observed execution or retrieval. Wiki redirect directives alone do not
establish a server-side fetch; ordinary public service URLs and text-search operands are not promoted.
Sanitized address pseudonyms still cannot establish original network scope.

### Analyzer 1.8.5 coverage

Adds standalone transfer commands, Windows file and diagnostic command syntax, server template arithmetic and
conditional probes (including encoded forms), quoted SQL comment tails, row-limit/constant/identity-function and
timer conditions, VALUES statements with functions or concatenation, remote style/embed markup and encoded active
HTML, and absolute server application class/library paths. On a sanitized production report this added 255
effective determinations (252 previously undetermined, 3 complete VALUES statements previously not_attack) with no
previously determined unit lost; one loopback image probe moved from ssrf to xss by category priority. Bare quotes,
native Solr local-params, CQL/JQL searches and JSON structure alone stay undetermined; these exclusions are by shape,
not a certification that the remaining values are benign.

### Request-path payloads (1.9.0)

Request paths that carry injection syntax are analysed too, as the pseudo-parameter `(uri path)` with the whole
URL-decoded path as its value: paths containing percent-escapes, `..`, `//` or any character outside letters, digits
and `/ . _ ~ ! * + , = : @ -`. Plain paths are not units, so ordinary crawling does not grow the analysis; the report
still lists every requested path as a target. `sanitize-input` keeps such paths readable: plain segments get `segN`
pseudonyms, the injection syntax stays, and host names or addresses inside it are pseudonymised. Other paths are
still replaced whole (`/pathN`). Exports that collapse requests by site, path and query keep one path unit per
distinct path.

Java path-parameter traversal (`..;/`, also with encoded dots, semicolon or slash) is `file_access`; a recognised
command after it keeps `rce` priority. Absolute local paths with ordinary punctuation or spaces and no traversal or
sensitive-file marker (`/docs/My File.pdf`, a `redirect=/home` value) are `not_attack`. On a sanitized production
report this moved 56 undetermined local-path values to not_attack and two traversal-only values from rce to
file_access; no determined unit was lost.

## HTML incident report

```
python -I report_builder.py payload_analysis.json -o report.html [--abuseipdb] [--ip-intel PATH] [--ioc-top 40]
```

Builds one offline HTML file (no network, inline CSS/JS/SVG): executive summary, attack
timeline and swimlanes, category/target/series/payload tables and an IOC relationship graph
(source IPs -> targets -> payload indicators -> techniques). Only rce/file_access/sqli/xss
units are described; everything else is a count. Data is embedded encoded and decoded in the
page. Output is deterministic for the same input and intel cache.

AbuseIPDB: set `ABUSEIPDB_KEY` in the environment (PowerShell: `$env:ABUSEIPDB_KEY = "..."`)
and pass `--abuseipdb`. Public source IPs of attack units and public IPs inside attack
payloads are looked up once and cached in `report.ip_intel.json` (or `--ip-intel PATH`);
later runs reuse the cache, and without `--abuseipdb` the cache is used offline.
`abuseipdb_check.py` does the same lookup standalone. The key is never written anywhere.

Report views (1.8.1):
- Timeline: colour by category, by source IP, or by probing / exploitation attempt; one swimlane per category
  and per source IP. Non-attack traffic from the attacking source IPs is drawn as a grey "related crawling" shadow.
- Probing vs exploitation attempt is derived from payload content only (not from the response): markers,
  identity/delay commands, existence checks and dictionary enumeration are probing; commands with an action
  program, file writes/exports, reads of application tables and real file targets are exploitation attempts.
- Values are never truncated. Clicking a row (evolution, payload, target) opens the full entry: every field, the
  inference comparison sequence and the full payload values. The inference table shows what each probe reads.
- The IOC graph uses one node per main entity: the file name for paths, the site or IP for URLs and UNC paths.
- No caps (1.9.4): every evolution row, payload id and full payload value is embedded and shown. Entry details list
  every payload of the selected row; tables render all rows; evolution values, DBMS markers, rule lists, source IP
  lists, campaign paths and narrative name lists are complete. Only the pictures aggregate: the source timeline
  stacks the top 8 sources plus "other sources", and the IOC graph draws the top indicators/targets (`--ioc-top`);
  long chart labels are shortened on screen with the full text on hover. Complete lists sit below each picture.
- The report data is embedded encoded (XOR + Base64) and decoded by the page, so searching the HTML file as text
  finds nothing. To check where a string occurs (1.8.4):
  `python -I report_builder.py payload_analysis.json --find example.com [--find other] [--html report.html]`
  prints its occurrences per category in the analysis (only rce/file_access/sqli/xss/ssrf are shown in the report),
  in the report data, and inside an existing HTML report (decoded in memory; nothing is written).
- Focus mode (1.8.5): type a domain, schema, IP or any text in the header box "Focus report on" and press Enter
  (or open `report.html?focus=TEXT`). The page keeps only attack payloads whose target site, path, parameter,
  decoded value, summary or source IP contains the text (case-insensitive) and rebuilds the executive summary,
  timeline, phases, evolution tables, campaigns, payload table and graph from them. A banner shows the match count and
  a "clear focus" link. The related-crawling shadow is limited to the source IPs of the matching payloads; campaign
  narratives and the unrelated-actions count stay global.
- Timeline range (1.8.6): the "Time range" selector above the timeline shows the whole period (attacks and related
  crawling), only the span of the attack requests (the default in focus mode) or a single attack phase, so short
  bursts inside a long period can be read minute by minute. Focus mode filters the timeline per request.
- Network artifacts from text (1.8.7): host names written anywhere in an attack payload (SQL string literals,
  compared values, database links such as `object@"link.example.int"`) are network artifacts, not only hosts inside
  URLs and network functions. A dotted name counts as a host when its last label is a well-known generic TLD
  (com, net, org, int, gov, edu, mil, info, biz, io, local, corp, internal...) or a two-letter country code with at
  least three labels, so schema.table and package.function names are not hosts; two-label country-code names
  (example.eu) written outside URLs are not picked up. In SQL, name@host outside quotes is a database link host;
  a quoted address stays an email.
- Source infrastructure (1.8.8): with AbuseIPDB data, every checked address is labelled by the network behind it,
  from AbuseIPDB's usage type and Tor flag: Tor exit, hosting / datacenter, residential / fixed-line ISP, mobile
  carrier, CDN, search engine crawler, organisation network, reserved, or unknown. The executive summary counts
  addresses and attack requests per type; the IP table, payload details and timeline legend show the label. The
  label describes the network only: a hosting or ISP address can still be a proxy or VPN exit, which AbuseIPDB does
  not establish.
- Blind inference (1.8.2): one row per extracted expression with the value read so far, e.g. `[AB][RS]T`
  (`[ab]` = one of, `Â·` = undetermined, `!` = inconsistent thresholds). The answer to the last comparison of each
  position is not in the request log, so a character usually narrows to two candidates; a stop does not prove an
  answer (checked against known values). Click a row for each position's comparisons (`63â†‘ 95â†“ â€¦ 65?`:
  arrow = direction of the attacker's next threshold). Literal check strings are verified against their bounds.

## Verification

```
py -I tests/fixtures/make_fixtures.py --assessor D:\Downloads\payload_assessor.py
py -I -m unittest discover -s tests -v
```

The retained gzip fixture contains 140 synthetic records processed by the real reference assessor. Generator source data is encoded at rest; plain intermediates are confined to a new/empty `E:\Temp\payload-analyzer\fixture-build` and removed in finally, unless `--keep-temp` is requested. The compact suite covers catalogue positives/near misses, evidence validation, unit error recovery, container round trips and plaintext exclusion, source scanning, and byte-identical assessor output. The reference comparison skips if its original is absent.

## Limits

Series member failures retain their pre-series nodes and analysis and record `series_error`; originally determined members stay determined, while other failed members remain variants without keyword-probe promotion. Inspect stderr for the unit and route.

Syntactic analysis is not full language interpretation. Unresolved aliases, concatenations, nested control flow and mixed-language constructions may remain undetermined; quoted code-like data can overlap supported syntax. No execution, timing, live lookup values, subsequent requests or transmission is established. Independent branches do not imply execution chronology. Unfamiliar timestamps sort lexically. Validation on real output used sanitized values only, which can obscure original indicators. This workspace is not a Git repository.
