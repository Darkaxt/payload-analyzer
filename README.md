# Payload Analyzer

Offline analysis of web-request exports (for example Splunk searches grouped by site, path and query) for
injection attempts, plus a self-contained HTML incident report. Python 3.10+, standard library only: no network
access (except the optional AbuseIPDB lookup), no model service, no payload execution.

- `payload_analyzer.py` decodes every query parameter (URL, Base64, compressed layers, embedded URLs) and request
  paths carrying injection syntax, then classifies each distinct value as `rce`, `file_access`, `sqli`, `xss`,
  `ssrf`, `not_attack` or `undetermined`, citing the exact decoded text behind every finding.
- `report_builder.py` turns the analysis into an offline HTML report: executive summary, attack timeline, phases,
  per-campaign attack evolution (SQL objects, blind-inference values, commands, files, callbacks), network
  artifacts, source infrastructure and a full payload table, with a focus filter (`report.html?focus=TEXT`).
- `payload_analyzer.py sanitize-input` pseudonymises hosts, addresses, e-mails and paths in the raw export so it
  can be shared while keeping the payload syntax.

## Quick start

```
python -I payload_analyzer.py pipeline export.json -o payload_analysis.json
python -I report_builder.py payload_analysis.json -o report.html
```

Optional: set `ABUSEIPDB_KEY` and add `--abuseipdb` to the report step to label source addresses.
`python -I report_builder.py payload_analysis.json --find TEXT` shows where a string occurs.

See [PAYLOAD_ANALYZER.md](PAYLOAD_ANALYZER.md) for the options, categories and limits.

## Input format

JSON Lines (`.json`/`.jsonl`, optionally `.gz` or `.pax`): one JSON object per line, one line per group of
identical requests. A Splunk JSON export works as is (each line is `{"preview":false,"result":{...}}`); a bare
object per line is accepted too. A JSON array or pretty-printed JSON is rejected.

| Field | Required | Meaning |
| --- | --- | --- |
| `site` | yes | Host name of the targeted site |
| `uri_path` | yes | Request path |
| `uri_query` | yes | Raw query string, still URL-encoded, with or without the leading `?` (string or list) |
| `src` | recommended | Source address (string or list) |
| `count` | recommended | Number of requests in the group (number or numeric string) |
| `et`, `lt` | recommended | First and last request time, `YYYY-MM-DD HH:MM:SS` or ISO 8601, UTC; epoch seconds are not placed on the timeline |
| `status`, `action` | optional | HTTP status and device action (string or list) |

Other fields are ignored. Example line:

```
{"result":{"site":"site1.invalid","uri_path":"/search","uri_query":"q=test%27","src":["192.0.2.10"],"count":"4","et":"2026-10-27 05:41:00","lt":"2026-10-27 05:44:10","status":["200","500"],"action":"allowed"}}
```

A Splunk search producing it (adapt the index and field names to your web or WAF logs), exported as JSON:

```
index=web site=* | stats count min(_time) as et max(_time) as lt values(src) as src values(status) as status values(action) as action by site uri_path uri_query
| eval et=strftime(et, "%Y-%m-%d %H:%M:%S"), lt=strftime(lt, "%Y-%m-%d %H:%M:%S")
```

Splunk's `strftime` uses the search head's time zone; set your Splunk user time zone to UTC before exporting, or
the report times will be shifted.

## Notes

- Detection tables are stored encoded and test strings are split so endpoint antivirus does not flag the
  sources; the HTML report embeds its data encoded for the same reason. This is obfuscation, not protection.
- Classifications describe the supplied syntax only. They do not establish that a request reached, executed on or
  affected the target.
- Run tests with `python -I -m unittest discover -s tests` (Node.js on `PATH` enables the report script checks).

## Licence

MIT No Attribution ([LICENSE](LICENSE)): do whatever you want with it. Credits are welcome but not required.
