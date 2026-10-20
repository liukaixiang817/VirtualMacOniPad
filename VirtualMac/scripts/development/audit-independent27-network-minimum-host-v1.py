#!/usr/bin/env python3
"""Finite, read-only network ingress inventory; never contacts a device."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
N = R / "DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm"
S = R / "VirtualMac/vz/host"


def pin(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def verify(row):
    actual = pin(row["path"])
    if actual != row:
        raise RuntimeError("Pinned input changed: " + row["path"])
    return actual


def load(path):
    return json.loads(Path(path).read_text())


def require(value, message):
    if not value:
        raise RuntimeError(message)


def line_of(path, literal):
    return next(i + 1 for i, line in enumerate(Path(path).read_text().splitlines())
                if literal in line)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    require(not out.exists(), "Output must be new; frozen reports are preserved")
    parent = N / "vz-filehandle-network-original-readonly-v1"
    parent_freeze = load(parent / "freeze.json")
    original_pins = [verify(row) for row in parent_freeze["files"]]
    inherited_pins = [verify(row) for row in load(parent / "inputs.json")]
    contract = load(parent / "contract.json")
    require(contract["originalVZUUID"] == "418efc4809d93606918eb6f95baeffdc",
            "Original27 frontend identity")
    require(contract["originalVZLoaded"] is False and
            contract["actualDatagramTransportImplemented"] is False,
            "Original method evidence is static only")
    base = contract["originalBase"]
    selected = {}
    for rva, selector in [(0x8ffbc, "initWithFileHandle:"), (0x90140, "_attachment")]:
        body = next(b for b in contract["actualBodies"]
                    if b["functionStart"] == base + rva)
        method = next(m for m in body["exactObjCIMPMatches"]
                      if m["className"] == "VZFileHandleNetworkDeviceAttachment" and
                      m["selector"] == selector)
        selected[selector] = {"RVA": rva, "method": method,
                              "bodySHA256": body["sha256"],
                              "resolvedSelectors": body["resolvedObjCMsgSendSelectors"]}
        if selector == "initWithFileHandle:":
            require(method["typeEncoding"] == "@24@0:8@16" and
                    method["typeEncodingVerified"], "Actual typed initializer")
            checks = {0x8fff4: "0x52800088", 0x90004: "0x529fffe1",
                      0x90008: "0x52820102", 0x90018: "0x7100091f",
                      0x9006c: "0x5280bb89"}
        else:
            checks = {0x90198: "0xb9000280", 0x9019c: "0xf9000688"}
        words = {i["rva"]: i["word"] for i in body["instructions"]}
        require(all(words.get(pc) == word for pc, word in checks.items()),
                "Actual socket type, MTU and descriptor machine words")
        selected[selector]["checkedMachineWords"] = checks
    require(any(x["selector"] == "fileDescriptor" for x in
                selected["_attachment"]["resolvedSelectors"]),
            "Original file handle accessor")

    app_candidate = N / "independent27-app-isolated-log-source-v8-attempt1/candidate.json"
    app = load(app_candidate)
    app_source = Path(verify(app["source"])["path"])
    app_text = app_source.read_text()
    at = app_text.index("static void configureNetwork(")
    branch = app_text[at:app_text.index("\n    }", at) + 6]
    require('setObj(configuration, "setNetworkDevices:", @[])' in branch and
            '[actualDevices count]!=0' in branch and "return;" in branch,
            "Actual first-display NIC0 guard")
    require(app["networkingAvailable"] is False and app["guestSSHAvailable"] is False,
            "No network or SSH success metadata")
    guest_tools = S / "VZGuestTools.m"
    tools_text = guest_tools.read_text()
    remote_at = tools_text.index("void VZGuestToolsEnableRemoteLogin(")
    remote = tools_text[remote_at:tools_text.index("\nstatic void ", remote_at)]
    require('VZGuestToolsRun(@"/bin/sh"' in remote and
            "system/com.openssh.sshd" in remote and
            'gGuestWriteDescriptor < 0' in remote,
            "Real agent request enables guest sshd only")
    require('"setSocketListener:forPort:"), listener, 505050' in tools_text and
            '@"guest-exec"' in tools_text and '@"capture-output": @YES' in tools_text,
            "Actual QGA request channel")
    require('kPencilVsockPort = 9949' in app_text and
            'S("connectToPort:completionHandler:")' in app_text and
            'gPencilVsockConnection = [connection retain]' in app_text,
            "Existing real VSOCK connector is Pencil scoped")
    vmnet = S / "vm27_vmnet_unavailable_v2.c"
    vmnet_text = vmnet.read_text()
    require("errno=ENOTSUP" in vmnet_text and "vmnet_read(" in vmnet_text and
            "vmnet_write(" in vmnet_text and "return VM27_VMNET_FAILURE" in vmnet_text,
            "Independent vmnet remains explicit failure")

    # Negative search is limited to available repository C/ObjC/C++ sources.
    # It does not claim that a network stack cannot exist outside these roots.
    query = ["rg", "-n", "-i", "libslirp|slirp_(new|init|input|pollfds|add_hostfwd)|"
             "lwip|pico[tT][cC][pP]|AF_VSOCK|sockaddr_vm",
             "VirtualMac/vz/host", "VirtualMac/vz/guest", "VirtualMac/vendor",
             "--glob", "*.{c,h,m,mm,cpp}"]
    result = subprocess.run(query, cwd=R, capture_output=True, text=True)
    require(result.returncode in (0, 1), "Source inventory search succeeded")
    require(result.returncode == 1, "New network source present: review it before retaining this inventory")
    sdk = Path("/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/System/Library/Frameworks/Virtualization.framework/Headers/VZFileHandleNetworkDeviceAttachment.h")
    require("connected datagram socket" in sdk.read_text() and
            "The default MTU is 1500" in sdk.read_text(), "Real SDK contract")
    source_pins = [pin(p) for p in [app_candidate, app_source, guest_tools,
        S / "VZGuestTools.h", vmnet, S / "vm27_vmnet_unavailable_v2.h",
        S / "vm27_vmnet_unavailable_v1.c", sdk,
        R / "VirtualMac/scripts/tests/check-ipad-guest-network.sh",
        R / "VirtualMac/scripts/build-ipad-vmnet.sh",
        R / "VirtualMac/scripts/build-ipad-network-sharing.sh"]]
    network_consumers = []
    for rva in [0x91560, 0x91964, 0x18fe68]:
        body = next(b for b in contract["actualBodies"]
                    if b["functionStart"] == base + rva)
        network_consumers.append({"RVA": rva,
            "methods": body["exactObjCIMPMatches"],
            "resolvedSelectors": body["resolvedObjCMsgSendSelectors"],
            "bodySHA256": body["sha256"]})
    report = {
        "schema": "Independent27 finite HOST network implementation inventory v1",
        "findings": [
            {"id": "NIC0", "impact": "The signed first-display App has zero actual networkDevices; no guest Ethernet or NAT route exists."},
            {"id": "VMNET_DISABLED", "impact": "The independent vmnet provider returns ENOTSUP. Legacy13 InternetSharing/vmnet cannot supply independence."},
            {"id": "NO_USER_NETWORK_STACK", "impact": "No libslirp/lwIP/picoTCP implementation or guest SSH-over-VSOCK bridge was found in the stated available source roots."},
            {"id": "FD_CHILD_CONSUMER_NOT_CLOSED", "impact": "The original27 datagram initializer and attachment producer are proved; actual descriptor serialization and child virtio-net consumption are not established by this existing contract."}],
        "controller3IndependentReview": pin(N / "independent27-final-firmware-products-controller-peer-v1-attempt1/controller-review.json"),
        "originalFileHandleEvidence": {"contract": pin(parent / "contract.json"),
            "freeze": pin(parent / "freeze.json"), "checkedFreezeMembers": len(original_pins),
            "checkedInheritedInputMembers": len(inherited_pins), "methods": selected,
            "existingNetworkConfigurationConsumerMethods": network_consumers,
            "privateAttachmentABIIsNotInvented": True,
            "connectedDatagramSocketRequired": True, "defaultMTU": 1500},
        "currentApp": {"source": pin(app_source),
            "configureNetworkLine": line_of(app_source, "static void configureNetwork("),
            "actualNICCount": 0, "actualGuestNetworkingValidated": False},
        "guestTools": {"source": pin(guest_tools),
            "agentPort": 505050, "enableRemoteLoginLine": line_of(guest_tools, "void VZGuestToolsEnableRemoteLogin("),
            "existingAgentRequest": "guest-exec and completion polling; enables guest sshd but exposes no host TCP listener or bidirectional SSH stream",
            "socketDeviceConfiguredOnlyIfToolsOrRemovalEnabled": True,
            "actualIndependent27AgentConnectionValidated": False},
        "existingPencilConnector": {"source": pin(app_source),
            "functionLine": line_of(app_source, "static void pencilVsockConnect(void) {"),
            "port": 9949, "selector": "connectToPort:completionHandler:",
            "connectionObjectRetainedForBorrowedDescriptor": True,
            "SSHBridgeImplemented": False},
        "sourceSearch": {"command": query, "returnCode": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr,
            "scope": "Available host, guest and vendor C/ObjC/C++ sources; no assertion about external installations"},
        "minimumCompleteNetworkPlan": [
            {"newSource": str(S / "vm27_owned_ethernet_attachment_v1.m"),
             "existingEntry": str(app_source) + ":" + str(line_of(app_source, "static void configureNetwork(")),
             "work": "In a new App version replace the independent NIC0 branch with an owned connected AF_UNIX/SOCK_DGRAM pair, NSFileHandle, original VZFileHandleNetworkDeviceAttachment and VZVirtioNetworkDeviceConfiguration. Keep exact VM-control queue ownership, MTU/buffer checks, both descriptor lifetimes and drain before VM release."},
            {"newSource": str(S / "vm27_owned_slirp_network_v1.c"),
             "work": "Pin and build the actual chosen libslirp source plus its required dependencies for iOS arm64e. Implement true Ethernet-frame input/output, polling, timers, wake and cleanup on one owner. DHCP/ARP/DNS/TCP must be handled by the real stack; a socket pair alone is insufficient."},
            {"newSource": str(S / "vm27_owned_slirp_network_v1.c"),
             "work": "Add a checked loopback TCP 22222 host-forward rule to guest port22 using the actual configured/observed guest address. Treat bind conflict or host-forward failure as failure; do not kill an unrelated old listener. Obtain guest DHCP and sshd evidence before claiming reachability."},
            {"work": "First close the original27 FD serializer and child virtio-net consumer from true source/bytes. Then validate real guest frames, DHCP, DNS/TCP, authenticated lkx SSH, teardown and Mac USB tunnel. No vmnet/InternetSharing13 fallback."}],
        "shorterSSHOnlyAlternative": {
            "existingHostConnector": "Actual Pencil connectToPort:completionHandler: code can inform a new, separate lifetime-safe VSOCK stream connector.",
            "requiredNewGuestSource": str(R / "VirtualMac/vz/guest/vm27_guest_vsock_ssh_relay_v1.c"),
            "requiredNewHostSource": str(S / "vm27_owned_vsock_ssh_relay_v1.m"),
            "work": "New guest VSOCK listener must relay both directions to localhost22, and a separate host TCP22222 listener must connect one actual VZ socket per accepted TCP connection, preserve connection ownership and half-close/backpressure. Deploy and verify the guest component through a true connected agent or actual guest setup.",
            "currentBridgeExists": False, "providesGuestInternetNetworking": False,
            "actualGuestAFVSOCKSupportValidated": False},
        "primaryResearch": [
            {"url": "https://raw.githubusercontent.com/utmapp/UTM/main/patches/sources", "fact": "UTM currently selects the libslirp4.9.1 release mirror; this repository has not imported it."},
            {"url": "https://raw.githubusercontent.com/utmapp/UTM/main/scripts/build_dependencies.sh", "fact": "UTM provides actual iOS-target flags and invokes the Darwin Meson libslirp build. Our arm64e compile is still unperformed."},
            {"url": "https://raw.githubusercontent.com/utmapp/libslirp/master/src/libslirp.h", "fact": "Existing primary API names include frame input/send_packet, poll callbacks, timer callbacks and host-forwarding. This fork master is old4.0.0; do not use its header as the unchecked4.9.1 ABI."},
            {"url": "https://github.com/qemu/qemu/blob/master/net/slirp.c", "fact": "Primary QEMU integration has checked host-forward setup and explicit failure handling."}],
        "historicalUSBRelayBoundary": "Old production socat/guest-DHCP routing evidence is historical and does not apply to NIC0 or prove any independent27 TCP route. A real loopback22222 listener would still need the USB or SSH tunnel and authenticated guest validation.",
        "sourcePins": source_pins, "inheritedInputPins": inherited_pins,
        "plannedSourcesImplemented": False, "existingIndependent27SSHBridge": False,
        "actualVZLoaded": False, "actualGuestNetworkingValidated": False,
        "actualGuestSSH22222Validated": False, "deviceOperations": 0,
        "nativeCPUCalls": 0, "trustCacheAdditions": 0,
        "frozenProductsModified": False, "finiteHostInventoryPassed": True}
    out.mkdir(parents=True)
    report_path = out / "report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    note = """当前独立27包没有来宾网卡或SSH桥。原27真实文件句柄网卡可接 connected datagram socket；仓库尚无其配套用户态网络栈。\n\n完整网络的最小接线是在新App configureNetwork版本中创建自有datagram pair与原VZFileHandleNetworkDeviceAttachment，再由新自有libslirp owner处理真实帧、poll、timer、DHCP和TCP22222→guest22。还需闭合原FD序列化到child virtio-net的真实消费者。旧13 VMNet/InternetSharing不可作为独立27路径。\n\n现VZGuestTools只经505050 QGA执行命令；EnableRemoteLogin开启sshd不创建路由。Pencil已有真正connectToPort接口，但只传9949输入数据。更短的SSH-only路径仍需新增guest VSOCK→localhost22双向代理和host TCP22222→VZsocket代理，不能称已有SSH桥，也不提供完整guest联网。\n\n本报告只完成HOST定位。未执行设备、VZ、网络栈、原guest或SSH。推荐的新文件名表示实现位置，文件尚未创建。\n"""
    (out / "minimum-network-plan.txt").write_text(note)
    freeze = {"schema": "Independent27 network HOST inventory freeze v1",
              "files": [pin(report_path), pin(out / "minimum-network-plan.txt"),
                        pin(__file__)] + source_pins + original_pins + inherited_pins}
    # Deduplicate identical provenance pins, preserving inspection order.
    unique = {}
    for row in freeze["files"]:
        require(row["path"] not in unique or unique[row["path"]] == row,
                "Consistent provenance pin")
        unique[row["path"]] = row
    freeze["files"] = list(unique.values())
    (out / "freeze.json").write_text(json.dumps(freeze, indent=2) + "\n")
    print(json.dumps({"report": pin(report_path), "freeze": pin(out / "freeze.json"),
                      "findings": len(report["findings"]),
                      "deviceOperations": 0}, indent=2))


if __name__ == "__main__":
    main()
