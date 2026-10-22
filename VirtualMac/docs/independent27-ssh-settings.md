# Guest SSH forwarding

The running VM's settings include an SSH page. Enable forwarding, select the
access scope and IP family, choose an iPad listening port, then use Apply Now.
The default is local IPv4 port22222. A stopped VM saves these options for its
next start. The SSH page reports the real listener and guest-channel status;
connected is not a claim that a user authenticated.

Local binds only loopback. LAN binds the selected families and accepts private,
link-local, loopback or directly attached subnet peers. Internet permits other
peers. Internet mode does not configure the router, UPnP, carrier NAT or a
firewall; externally reachable addresses and routing must already exist.
IPv6 listeners are separate V6ONLY sockets. This host forwarding feature is
independent of the guest's current IPv4 NAT internet connection.

Changing listeners drains the current owned VZ connection, creates the new
listeners on the same running VM and saves only the four SSH options. Existing
SSH sessions disconnect. A binding failure attempts to restore the former
listener and reports the error. Pause and normal guest stop retain their
native lifecycle ownership checks.

The actual Apple guest agent enables native OpenSSH and installs the signed
owned relay as a persistent launchd job. It waits for genuine guest-agent
readiness and an available original QGA operation lease before consuming a
provisioning attempt. Helper bytes use the existing4096-byte file-write API;
partial or stale requests are not replayed. A new relay job runs as nobody;
the precisely identified existing job is preserved on upgraded guests.
Disabling host forwarding closes iPad listeners; guest OpenSSH remains enabled
across guest starts. Existing guest SSH account authentication is unchanged.

Device checks completed on the current macOS27 graph include live off/on,
IPv4 and IPv6 loopback SSH host-key exchange, switching to22224 and restoring
22222, plus authenticated guest SSH. Socket fixtures also cover all three
scope policies, bind collisions, stale tokens and control-channel reconnect.
An external WAN connection and a clean guest installation are separate device
acceptance items; they must not be inferred from loopback tests.

Long native pause can leave an apparently connected control channel unable to
open new streams. Reapplying the same listener settings on the actual device
restored authenticated SSH without changing the guest. App239 now runs that
existing controlled drain/recreate operation after a verified native Resume.
Existing SSH sessions may disconnect across pause/resume; new authentication
uses the same guest account. Final packaged-device native Resume followed by authenticated SSH passed on the
complete macOS27 graph. Whole13 authenticated SSH and HTTPS also passed after
App241 switched to the original explicit-queue initializer; macOS13 has no
public VM queue getter. Framework aliases must resolve to the same admitted
image, and the original VM queue, listener ABI and ownership checks remain.
