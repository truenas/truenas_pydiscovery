# browse/

Host-announcement cadence and browser-election payloads on port
138 per [MS-BRWS].

- `announcer.py`:
  - `BrowseAnnouncer` — sends periodic HostAnnouncements to
    `WORKGROUP<0x1d>` via the `\MAILSLOT\BROWSE` datagram
    (MS-BRWS §2.2.1).  Announcement intervals start at 1 minute
    and double to a 12-minute cap, matching nmbd behaviour.
    Payload includes server-type flags, OS version, and
    server-description string.  Wired up per subnet in
    `server.server._setup_subnet`.  `set_hostname`,
    `set_workgroup`, and `set_server_string` update the cached
    fields in place so the SIGHUP live-update reload can change
    announcement payloads without cancelling the announce loop —
    the next iteration picks up the new values.
  - MS-BRWS payload builders used by callers that want to
    construct these frames without running the periodic loop:
    - `build_host_announcement(...)` — §2.2.1 HostAnnouncement
      (opcode 0x01); same layout as the cadence-driven flavour.
    - `build_domain_announcement(...)` — §2.2.3
      DomainAnnouncement (opcode 0x0C) from domain master
      browsers.
    - `build_local_master_announcement(...)` — §2.2.6
      LocalMasterAnnouncement (opcode 0x0F) from the local
      master browser.
    - `build_election_request(...)` / `parse_election_request(...)`
      — §2.2.19 ElectionRequest (opcode 0x08) for browser-election
      criteria exchange.

Note: we emit HostAnnouncements but do NOT participate in browser
elections or take the Local Master Browser role.  See the
[package-level limitations](../../README.md#limitations).  The
election builders above are present for callers that want to
originate elections externally.
