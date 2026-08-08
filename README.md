# RouterOS Suspension (Comsat)

Fork of `routeros-suspension` that resolves each client's IP address(es) from a **CLIENT custom attribute** (the same attribute filled by `ip-address-sync` / used by `quesync-comsat`) instead of resolving them from UISP's Network (NMS) app.

## How it differs from `routeros-suspension`
- No `unmsApiToken` config / no NMS API calls for IP resolution.
- New **IP Address Custom Attribute Name** config field (default `IP Address`).
- The attribute value may contain multiple comma-separated IPs (e.g. `10.0.0.5, 10.0.0.6`) - all are blocked/unblocked together for that client.
- Everything else (walled garden, NAT/filter rules, prepaid period re-check, webhook events, subnet filtering, SSE bulk sync) is unchanged from `routeros-suspension`.

## Bulk sync UI
- **Start Sync** runs Phase 1 (firewall rules to all devices) -> Phase 2 (build the block IP list from UISP, once) -> Phase 3 (apply the address list to all devices).
- **Continue Sync** resumes an interrupted run: already-completed devices in Phase 1 / Phase 3 are skipped, and a cached IP list from Phase 2 is reused instead of rebuilding it from scratch.
- **Download CSV** exports the list of clients that were candidates for suspension but had no resolvable IP in the custom attribute.

## Changelog
### v1.0.0
- Initial fork of `routeros-suspension` v1.8.1, adapted to resolve client IPs from a custom attribute instead of NMS.
- Added resumable bulk sync (checkpoint file + Continue button), mirroring `ip-address-sync`.
- Added CSV export of clients skipped due to a missing/invalid IP attribute.
