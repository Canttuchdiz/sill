# Personal fork: access after the Mac locks

Fork: https://github.com/Canttuchdiz/sill

## Required behavior

Connect from an already paired iPhone or iPad after the Mac has locked, including
when no Sill client was connected at the time of locking. Preventing automatic
locking is not a substitute. This document records an investigation and proposed
implementation; the fork does not yet implement locked access.

Two outcomes need separate validation: remotely authenticating at the lock screen
and then using the unlocked session, versus using a desktop while the local
console remains locked. The second outcome requires an isolated remote session
or an equivalent system facility; it must not be inferred from the first.

## Findings at upstream 4d990e9

- `Sources/SillMenuBar/AppModel.swift`, `holdAppNapOff`: an active remote client
  already gets a user-initiated activity that prevents idle system sleep. This
  neither unlocks the graphical session nor holds the Mac awake between clients.
- `Sources/SillHost/WindowCapture.swift`: uses ScreenCaptureKit and forwards only
  complete video frames. A suspended/blank stream can leave the last frame visible.
- `Sources/SillHost/StreamCoordinator.swift`, `capture.onStopped`: a capture error
  selects `.none`; this path does not remember a source for recovery on unlock.
- `Sources/SillHost/InputInjector.swift`: uses CGEvents and Accessibility in the
  logged-in user's session. This is not an authenticated login-screen backend.
- `Sources/SillHost/SessionLock.swift`: protects requests to pair new devices.
  Its callers do not impose a blanket lock prohibition on already paired clients.
  Removing this guard would weaken pairing without solving capture or input.
- `Sources/SillHost/KeychainIdentityStore.swift`: the release identity store is
  designed for access after first unlock. Personal development builds use the
  login keychain; verify that identity loading on a cold reconnect still succeeds.
- `docs/DEVELOPMENT.md`, the restore probe: upstream records that Accessibility
  lists no windows while locked. A virtual display must not be assumed to bypass
  the session boundary.

These findings explain why a running process reachable through a CLI can remain
useful while Sill's graphical pipeline cannot. They do not establish the exact
runtime failure on this Mac; reproduce it before changing capture behavior.

## Recommended sequence

1. Establish a baseline using a paired client. Test an existing stream across
   lock, a fresh connection after lock, display sleep without lock, and unlock.
   Record listener/TLS success, capture status/error, window enumeration and input
   results separately. Test both window and desktop modes. Do not log passwords,
   pairing secrets, clipboard contents, or screen pixels in diagnostics.
2. Prove an authenticated system backend before implementing an RFB client.
   Manually enable macOS Screen Sharing for the intended user and test a compatible
   client over the private network/VPN. Verify an ordinary macOS lock (not just
   Remote Desktop's distinct screen-lock command), fresh authentication, pointer
   and keyboard control, reconnect, and what the physical display shows. Repeat
   after the display sleeps. Stop if the required behavior cannot be demonstrated.
3. If that succeeds, add an explicitly configured full-desktop fallback to Sill.
   The existing ScreenCaptureKit path remains for window streaming. Introduce a
   backend interface for video, input and session lifecycle. The system service
   owns login-screen authentication and input; Sill's CGEvents do not take over
   the login screen. Determine the supported RFB authentication/security types
   during the spike rather than assuming generic VNC support is sufficient.
4. For integrated use, keep the system service on the Mac and route it only through
   an authenticated, paired Sill connection to a fixed loopback destination. Do
   not implement a general port proxy. The iOS client needs a compatible RFB
   decoder/input backend, explicit capability negotiation and a remote-login UI.
   Validate the encryption/authentication chain; do not downgrade authentication
   to make a client work. An App Store Sill client cannot gain this new backend
   from a host-only change.
5. Add explicit states for locked, authenticating, connected and recovering. Never
   show a stale frame as a working live connection. Preserve the previous source
   and resume it after authentication/unlock if it still exists. Keep new-device
   pairing restricted to the unlocked Mac. Test source closure during the lock,
   repeated lock/unlock, disconnect/reconnect and a revoked paired device.
6. Separately address availability between connections with an opt-in idle-sleep
   hold while remote availability is enabled. A sleep hold is not a lock bypass
   and does not guarantee operation after closing a laptop lid. Reboot before
   first FileVault unlock is outside this logged-in-session design.

If using the desktop while the physical console stays locked is mandatory and
the system backend cannot provide it, investigate a supported separate remote
login session or a VM. Do not present screen blanking, disabling the password,
or stored-password auto-unlock as equivalent behavior.

## Personal builds

On 2026-10-22, the unmodified Mac host compiled successfully with Xcode 26.2 on
macOS 26.6.2:

```sh
swift build -c release --product SillMenuBar
Scripts/make-app.sh
```

The second command packages `.build/Sill.app`. It does not install or launch it.
To install deliberately, use `Scripts/make-app.sh --install --open`; that replaces
`/Applications/Sill.app`. A personal build needs its own permission grants and
pairing. Without a development signing identity, ad-hoc builds may need new
Screen Recording and Accessibility grants after rebuilding.

For an integrated fallback, build the modified iOS app too: choose your own team
and bundle identifier in `iOSClient/Sill.xcodeproj`. Upstream documents Xcode 27.1
for the current iOS source. The successful Mac build does not verify the iOS build.

## References

- [Apple: Screen Sharing setup and VNC compatibility](https://support.apple.com/en-gb/guide/mac-help/mh11848/27/mac/27)
- [Apple: remote session selection](https://support.apple.com/en-in/guide/remote-desktop/apd4f46319e/mac)
- [Apple: Remote Desktop's own lock-screen command](https://support.apple.com/guide/remote-desktop/lock-or-unlock-a-screen-apd37d6089c/mac)
- [Upstream development instructions](https://github.com/Saffsanity/sill/blob/main/docs/DEVELOPMENT.md)

Apple's documentation establishes available system services, not that an arbitrary
RFB implementation meets this fork's lock-screen requirements. The feasibility
test above remains a prerequisite to choosing that architecture.

## First development checkpoint

The owner approved enabling macOS Screen Sharing. The UI was verified with only
the owner's user in the access list, public permission requests off, and
password-only VNC off. No credentials were entered by the development tools.

The service responded with `RFB 003.889` and security types `[30, 33, 36, 35]`.
Type 30 is Apple ARD; types 33, 36 and 35 are preserved as numbers, without
claiming their authentication or encryption semantics. The service does not
advertise None (1) or password-only VNC (2).

`Scripts/locked_access_probe.py` provides reproducible discovery:

```sh
python3 Scripts/locked_access_probe.py
python3 Scripts/locked_access_probe.py --samples 12 --interval 5
Tests/checks/run-all.sh locked-access
```

It connects only to `127.0.0.1:5900`, sends a protocol-version reply and closes
before selecting authentication. It does not read screen pixels or take
credentials. Each sample has a total operation deadline (including partial
reads), bounded payloads and no internal retries. Sampling is sequential and
limited to 120 attempts, with at least a second between completed attempts.
The JSON explicitly reports that authentication and locked access are untested.
Output contains no server-supplied error messages or device/user identifiers.

Twenty automated tests cover all truncations of the Apple discovery reply,
single-byte fragmentation, coalesced replies, 3.3/3.7/3.8/Apple version framing,
unknown versions, malformed greetings, refusal, duplicate/invalid security types,
maximum-size type lists, total-deadline enforcement, refusal versus network
failure, cleanup, bounded CLI parameters, interruption, sequential sampling,
a real stalled socket, and a loopback server accepting two fresh connections.
The check is discovered automatically by the existing `run-all.sh` and CI.

Local regression baseline: the full run covered 47 suites in 368 seconds; 46
passed and `duo` hit Xcode 26.2's expression type-checking limit. After simplifying
two test-only expressions, `duo` passed all 252,557 checks on its targeted rerun.
The final expanded `locked-access` suite passed 20 tests. No production capture,
authentication, network transport or input behavior has been changed yet. CI has
not been verified for this fork. The app-control tool could not open the installed
Sill host for a live reproduction; a host/phone session is still required.

Six fresh connections to the actual local service succeeded: first discovery
430.89 ms, subsequent discoveries 2.54–7.13 ms. These are local handshake timings,
not authentication or video latency measurements. Authentication, lock-screen
control, cellular/VPN reachability and Sill fallback integration remain unverified.

The owner uses NordVPN Meshnet, not Tailscale. NordVPN's UI showed Meshnet on,
the paired iPhone online, and remote access allowed in both directions. A stopped
Tailscale installation is irrelevant to this setup. Preserve the existing Meshnet
configuration and validate cellular reachability through it; no VPN migration is
needed. NordVPN VPN-server connectivity and Meshnet connectivity are separate.

## Acceptance and performance gates

| Scenario | Expected result | Verification |
| --- | --- | --- |
| No client connected; lock; connect later | Authenticate and reach the intended session | Phone + real service; pending |
| Phone on cellular with VPN | Same behavior as local connection | Phone + real network; pending |
| Wrong/cancelled authentication | No desktop, no saved password, bounded retry | Real backend + integration; pending |
| VPN absent or interrupted | Clear reachability error; cancellable reconnect with backoff | Fault injection + phone; pending |
| Lock while viewing; repeated lock/unlock | Clear state, no stale live picture; source resumes if present | Integration; pending |
| Window closes while locked | Recover to source selection without retrying a dead window | Integration; pending |
| Device removed from paired list | New connections and active fallback lose access | Security integration; pending |
| New unpaired device while locked | No automatic pairing or login fallback | Existing rules + integration; pending |
| Display sleeps, system remains awake | Fresh reconnect still works | Real hardware; pending |
| Lid closure, logout, reboot before FileVault unlock | Report unavailable; no claim of recovery | Real hardware; outside initial guarantee |
| Fragmentation, EOF, malformed reply, slow peer | Bounded error, cleanup, no auth downgrade | Discovery tests pass |
| Multiple clients or a late callback after disconnect | Session isolation; no cross-client input or credentials | Integration; pending |

For an implemented backend, measure cold-connect/authentication time, first-frame
time, input-to-visible-response latency, CPU, memory and bandwidth separately.
Compare against the current host on the same device, window, resolution and VPN
path. Idle/locked/disconnected states must have no polling spin, unbounded queues,
or accumulating connections/tasks. A slow link must not grow a stale frame queue.
Run a sustained session, repeated reconnections, and a throttled/dropped-link test
before calling the feature ready. The protocol probe's timings cannot substitute
for these measurements.
