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

See [PAYLOAD_ANALYZER.md](PAYLOAD_ANALYZER.md) for the input format, options, categories and limits.

## Notes

- Detection tables are stored encoded and test strings are split so endpoint antivirus does not flag the
  sources; the HTML report embeds its data encoded for the same reason. This is obfuscation, not protection.
- Classifications describe the supplied syntax only. They do not establish that a request reached, executed on or
  affected the target.
- Run tests with `python -I -m unittest discover -s tests` (Node.js on `PATH` enables the report script checks).
