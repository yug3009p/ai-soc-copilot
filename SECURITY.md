# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Report it privately through GitHub's
**Report a vulnerability** button on the repository's Security tab, or by email to
yug3009p@gmail.com. Include steps to reproduce. Never send real alerts or logs from an
organisation.

You can expect an acknowledgement within 7 days. This is a personal open-source project, so fixes
are best-effort.

## How the app treats data

- **Alert text is sent to Groq** to be analysed. Only paste alerts you are allowed to share with a
  third-party API. Analyses are stored locally in `analyses.json`, which is git-ignored.
- **Alerts are untrusted.** They come from possibly compromised systems and can contain text
  written to manipulate the model. The prompt tells the model not to follow such instructions, and
  all model output is HTML-escaped before it is displayed. Model output is advisory.
- **No live threat-intel lookups** are made; any reputation claim in a result comes from the model.

## Scope

In scope: this repository's code. Out of scope: vulnerabilities in dependencies or in Groq's
service (report those upstream).
