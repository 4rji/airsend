# AirSend 3.0 — Release Notes

_Released June 27, 2026_

This release adds **reusable download links** and makes **share codes forgiving of case**, so a code typed on a phone or Mac — where autocorrect loves to capitalize the first letter — just works.

---

## New Features

### Multiple downloads per upload — `-f -n<N>`

By default, a file sent through the relay is a one-shot pickup: it is removed the moment it is downloaded once. The new `-n<N>` flag lets a single upload be downloaded up to **N** times before it is removed — no need to re-send the file for each recipient.

- **Range:** `1`–`25`. Values above 25 are clamped to 25; the default (no flag) is `1`.
- **Cross-transport:** the remaining-download counter is shared between the QUIC CLI receiver (`-r`) and the web/HTTP download endpoint, so any mix of clients can pull the same upload until the slots run out.
- **Flexible syntax:** both the attached form `-n3` and the separated form `-n 3` are accepted, and the flag may appear anywhere in the `-f` arguments.

```bash
# Allow the file to be downloaded 3 times
airsend -f -n3 report.pdf

# 10 downloads, custom code, explicit relay host/port
airsend -f -n10 mycode relay.example.com 443 report.pdf
```

The sender prints how many downloads are allowed, and the relay logs the remaining count on each pickup (`remaining=N` in `connections.log`). When the count reaches zero the file is deleted, exactly like the classic one-shot behavior.

### Case-insensitive share codes

Share codes are now matched **case- and whitespace-insensitively**. A code created as `wave21` matches `WAVE21`, `Wave21`, or `  wave21  `. This fixes the common annoyance where a mobile keyboard or macOS autocorrect capitalizes the first letter of a typed code and breaks the match.

- Normalization happens **server-side** at every point a code enters the system, so it applies uniformly to **files and chat** across the CLI, the web UI, and the desktop app.
- The macOS desktop app's code inputs additionally set `autocapitalize="off"` / `autocorrect="off"`, so the capital letter no longer appears in the first place.

---

## Upgrade Notes

- Both features live in the **relay/server**, so the server your clients connect to must run the 3.0 binary. Rebuild with `make build` and redeploy it.
- `-n` sends the download count alongside the file size on the wire; a pre-3.0 server will reject an `-n` upload. Sending **without** `-n` stays fully backward compatible with older servers.
- For the desktop app input changes, rebuild the app with `wails build` from `airsend-app/`.

## Compatibility

| Scenario | Behavior |
|----------|----------|
| 3.0 client + 3.0 server | Full support for `-n` and case-insensitive codes |
| Old client + 3.0 server | Codes are still matched case-insensitively (server-side); one-shot downloads as before |
| 3.0 client (no `-n`) + old server | Works as before — wire format is unchanged |
| 3.0 client (`-n`) + old server | Upload rejected — update the server to use `-n` |
