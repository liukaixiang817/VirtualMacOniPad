"""Generic BTVC LE peer backed by actual host GATT operations.

No device names or HID UUIDs select behavior. Bumble owns ATT/L2CAP/SMP;
this adapter owns the audited 25G83 software link format. The backend must
verify the current guest pairing ticket before creating any physical bond.
Keys and GATT values are protocol data, never diagnostic output.
"""
import asyncio
import secrets
import struct
import sys

from bumble import att, core, hci, ll
from bumble.controller import Controller, Connection as ControllerConnection
from bumble.device import Device, DeviceConfiguration
from bumble.gatt import Characteristic, CharacteristicValue, Descriptor, Service
from bumble.host import Host
from bumble.keys import MemoryKeyStore
from bumble.pairing import PairingConfig, PairingDelegate

from btvc_peer_crypto_v1 import BTVCEncryptionV1, derive_session_key


def native_address(value):
    if not isinstance(value, bytes) or len(value) != 7 or value[6] not in (0, 1):
        raise ValueError("invalid virtual link address")
    return hci.Address(value[:6][::-1], value[6])


class BTVCLinkV1:
    """Packet framing, fragment bounds and cryptographic handshake state."""

    FEATURES = 0x3D  # Encryption, extended reject, peripheral features, ping, DLE.

    def __init__(self, send, on_l2cap, on_encryption_request, on_encrypted, on_close):
        self._send = send
        self._l2cap = on_l2cap
        self._encryption_request = on_encryption_request
        self._encrypted_callback = on_encrypted
        self._close_callback = on_close
        self._fragment = bytearray()
        self._expected = 0
        self._cipher = None
        self._enc_request = None
        self._encrypted = False
        self._closed = False

    def __repr__(self):
        return "<BTVCLinkV1: redacted>"

    def close(self):
        if self._closed:
            return
        self._closed = True
        self._fragment.clear()
        self._cipher = self._enc_request = None
        self._close_callback()

    def _output(self, header, payload, plaintext=False):
        if self._closed or len(payload) > 251:
            raise ValueError("link output unavailable or too large")
        packet = {"header": header, "payload": bytes(payload)}
        if self._cipher and not plaintext:
            packet["payload"], packet["MIC"] = self._cipher.encrypt(bytes(payload))
        self._send(packet)

    def send_l2cap(self, data):
        if len(data) < 4 or len(data) > 65539 or int.from_bytes(data[:2], "little") + 4 != len(data):
            raise ValueError("invalid outgoing L2CAP frame")
        for offset in range(0, len(data), 251):
            self._output(2 if offset == 0 else 1, data[offset:offset + 251])

    def key_available(self, key):
        if self._closed or self._enc_request is None or self._cipher:
            return
        if key is None or len(key) != 16:
            self._output(3, b"\x11\x03\x06", plaintext=True)
            self._enc_request = None
            return
        request = self._enc_request
        skd = secrets.token_bytes(8)
        iv = secrets.token_bytes(4)
        session_key = derive_session_key(key, request[11:19], skd)
        # Native BTVCEncryption(role=0/central) uses direction one for TX;
        # its peripheral counterpart therefore uses direction zero for TX.
        self._cipher = BTVCEncryptionV1(session_key, request[19:23] + iv, 0)
        self._output(3, b"\x04" + skd + iv, plaintext=True)
        self._output(3, b"\x05", plaintext=True)

    def feed(self, packet):
        try:
            self._feed(packet)
        except Exception:
            self.close()
            raise

    def _feed(self, packet):
        if self._closed:
            raise RuntimeError("link closed")
        if not isinstance(packet, dict) or type(packet.get("header")) is not int:
            raise ValueError("invalid link packet")
        header, payload = packet["header"], packet.get("payload")
        if header not in (1, 2, 3) or not isinstance(payload, bytes) or len(payload) > 251:
            raise ValueError("invalid link packet")
        if "MIC" in packet:
            if not self._cipher:
                raise ValueError("encrypted packet without a link key")
            payload = self._cipher.decrypt(payload, packet["MIC"])
        elif self._cipher:
            raise ValueError("plaintext packet after encryption start")
        if header == 3:
            self._control(payload)
            return
        if self._cipher and not self._encrypted:
            raise ValueError("data before encrypted handshake completion")
        if header == 2:
            if self._fragment or len(payload) < 4:
                raise ValueError("overlapping or truncated L2CAP frame")
            self._expected = int.from_bytes(payload[:2], "little") + 4
            if self._expected > 65539:
                raise ValueError("L2CAP frame exceeds bounds")
        elif not self._fragment:
            raise ValueError("orphan L2CAP continuation")
        self._fragment.extend(payload)
        if len(self._fragment) > self._expected:
            raise ValueError("L2CAP frame exceeds declared length")
        if len(self._fragment) == self._expected:
            complete = bytes(self._fragment)
            self._fragment.clear()
            self._expected = 0
            self._l2cap(complete)

    def _control(self, payload):
        if not payload:
            raise ValueError("empty LL control")
        opcode = payload[0]
        if opcode == 0x0C and len(payload) == 6:
            # Owned software proxy's version, not a claim about host RF silicon.
            self._output(3, b"\x0c\x08\xff\xff\x01\x00")
        elif opcode in (0x08, 0x0E) and len(payload) == 9:
            self._output(3, b"\x09" + self.FEATURES.to_bytes(8, "little"))
        elif opcode == 0x14 and len(payload) == 9:
            self._output(3, b"\x15" + struct.pack("<HHHH", 251, 2120, 251, 2120))
        elif opcode == 0x12 and len(payload) == 1:
            self._output(3, b"\x13")
        elif opcode == 0x16 and len(payload) == 3:
            self._output(3, b"\x17\x01\x01")
        elif opcode == 0x03 and len(payload) == 23:
            if self._enc_request is not None or self._cipher:
                raise ValueError("overlapping encryption request")
            self._enc_request = bytes(payload)
            self._encryption_request(payload[1:9], int.from_bytes(payload[9:11], "little"))
        elif opcode == 0x06 and len(payload) == 1:
            if not self._cipher or self._encrypted:
                raise ValueError("unexpected encryption response")
            # Reaching here required a valid MIC with the negotiated key.
            self._output(3, b"\x06")
            self._encrypted = True
            self._encrypted_callback()
        elif opcode == 0x02 and len(payload) == 2:
            self.close()
        elif opcode in (0x07, 0x09, 0x0D, 0x11, 0x13, 0x15, 0x17, 0x18):
            return
        else:
            self._output(3, b"\x07" + bytes([opcode]))


class _NativeLink:
    def __init__(self, owner):
        self.owner = owner

    def add_controller(self, controller):
        self.controller = controller

    def on_address_changed(self, controller):
        pass

    def send_acl_data(self, sender, destination, transport, data):
        if transport != core.PhysicalTransport.LE:
            raise ValueError("unsupported transport on LE peer")
        self.owner.link.send_l2cap(data)


class _NativeController(Controller):
    def on_le_long_term_key_reply(self, connection, request, long_term_key):
        # Native BTVC's EncReq carries SKD/IV instead of the peer LTK. Possession
        # is verified by CCM in BTVCLinkV1, before reporting encryption success.
        self.link.owner.link.key_available(long_term_key)


class _GuestPairingDelegate(PairingDelegate):
    def __init__(self, owner):
        super().__init__(io_capability=PairingDelegate.NO_OUTPUT_NO_INPUT)
        self.owner = owner

    async def accept(self):
        result = await self.owner.backend({"operation": "pair"})
        self.owner._physical_paired = result.get("ok") is True and result.get("paired") is True
        print("VM27PeerWorker physicalBondVerified=" + str(int(self.owner._physical_paired)), file=sys.stderr, flush=True)
        return self.owner._physical_paired


class BTVCGattPeerV1:
    def __init__(self, send, backend, closed, key_store=None):
        self.backend = backend
        self._closed = closed
        self._tasks = set()
        self._characteristics = {}
        self._bond_store = key_store or MemoryKeyStore()
        self._notifications = asyncio.Queue(maxsize=128)
        self.link = BTVCLinkV1(send, self._l2cap, self._encryption_request, self._encrypted, self.close)

    def __repr__(self):
        return "<BTVCGattPeerV1: redacted>"

    async def start(self, peripheral, central, metadata):
        self._physical_paired = metadata.get("paired") is True
        self._central_address, self._peripheral_address = native_address(central), native_address(peripheral)
        self.controller = _NativeController("VirtualMac shared LE", link=_NativeLink(self), public_address=self._peripheral_address)
        self.controller.le_features = hci.LeFeatureMask(BTVCLinkV1.FEATURES)
        config = DeviceConfiguration(name=metadata.get("name", "VirtualMac shared device"),
            address=self._peripheral_address, gap_service_enabled=False, gatt_service_enabled=False)
        self.device = Device(config=config, host=Host(self.controller, self.controller))
        self.device.keystore = self._bond_store
        self.device.pairing_config_factory = lambda connection: PairingConfig(sc=True, mitm=False,
            bonding=True, delegate=_GuestPairingDelegate(self))
        self._add_services(metadata["services"])
        await self.device.power_on()
        self.controller.random_address = self._peripheral_address
        connection = ControllerConnection(self.controller, 1, hci.Role.PERIPHERAL,
            self._peripheral_address, self._central_address, self.controller.link,
            core.PhysicalTransport.LE, hci.HCI_Connection_Complete_Event.LinkType.ACL)
        self.controller.le_connections[self._central_address] = connection
        self.controller.send_hci_packet(hci.HCI_LE_Connection_Complete_Event(status=0,
            connection_handle=1, role=hci.Role.PERIPHERAL, peer_address_type=self._central_address.address_type,
            peer_address=self._central_address, connection_interval=24, peripheral_latency=0,
            supervision_timeout=500, central_clock_accuracy=0))
        await asyncio.sleep(0)
        self._spawn(self._deliver_notifications())
        self.device.connections[1].on("pairing", lambda *unused: print("VM27PeerWorker virtualSMPCompleted physicalBondVerified=" + str(int(self._physical_paired)), file=sys.stderr, flush=True))

    async def _operation(self, request):
        result = await self.backend(request)
        if result.get("ok") is not True:
            code = result.get("nativeError", 0x0E) if result.get("ATTError") else 0x0E
            raise att.ATT_Error(code if type(code) is int and 1 <= code <= 255 else 0x0E)
        return result

    def _value(self, identifier, properties=0):
        async def read(connection):
            result = await self._operation({"operation": "read", "attribute": identifier})
            value = result.get("value")
            if not isinstance(value, bytes) or len(value) > 512:
                raise att.ATT_Error(0x0E)
            return value

        async def write(connection, value):
            await self._operation({"operation": "write", "attribute": identifier,
                "value": bytes(value), "withResponse": bool(properties & 8)})
        return CharacteristicValue(read=read, write=write)

    def _spawn(self, coroutine):
        task = asyncio.create_task(coroutine)
        self._tasks.add(task)
        def done(future):
            self._tasks.discard(future)
            if not future.cancelled() and future.exception() is not None:
                self.close()
        task.add_done_callback(done)

    def _add_services(self, services):
        if not isinstance(services, list) or len(services) > 128:
            raise ValueError("invalid service metadata")
        identifiers = set()
        for service in services:
            characteristics = []
            for row in service["characteristics"]:
                identifier, properties = row["id"], row["properties"]
                if not isinstance(identifier, str) or identifier in identifiers or len(identifiers) >= 4096:
                    raise ValueError("invalid attribute identity")
                identifiers.add(identifier)
                if type(properties) is not int or not 0 <= properties <= 0x3FF:
                    raise ValueError("invalid characteristic properties")
                descriptors = []
                for descriptor in row["descriptors"]:
                    # CCCD is connection-local and owned by Bumble, while its
                    # subscription event is forwarded to the actual host peer.
                    if descriptor["uuid"].upper() == "2902":
                        continue
                    descriptors.append(Descriptor(descriptor["uuid"], att.Attribute.READABLE,
                        self._value(descriptor["id"])))
                permissions = (att.Attribute.READABLE if properties & 2 else 0) | (att.Attribute.WRITEABLE if properties & 12 else 0)
                characteristic = Characteristic(row["uuid"], Characteristic.Properties(properties & 255), permissions,
                    self._value(identifier, properties), descriptors)
                self._characteristics[identifier] = characteristic
                async def subscribe(connection, notify, indicate, identifier=identifier):
                    await self._operation({"operation": "notify", "attribute": identifier, "enabled": bool(notify or indicate)})
                def subscribed(connection, notify, indicate, callback=subscribe):
                    self._spawn(callback(connection, notify, indicate))
                characteristic.on(characteristic.EVENT_SUBSCRIPTION, subscribed)
                characteristics.append(characteristic)
            self.device.add_service(Service(service["uuid"], characteristics, primary=service.get("primary", True)))

    def _l2cap(self, data):
        self.controller.on_link_acl_data(self._central_address, core.PhysicalTransport.LE, data)

    def _encryption_request(self, rand, ediv):
        if not self._physical_paired:
            self.link.key_available(None)
            return
        connection = self.controller.le_connections[self._central_address]
        self.controller.on_le_encryption_request(connection, ll.EncReq(rand, ediv, b""))

    def _encrypted(self):
        self.controller.on_le_encryption_change(self.controller.le_connections[self._central_address], 0)

    def feed(self, packet):
        self.link.feed(packet)

    async def notification(self, identifier, value):
        characteristic = self._characteristics.get(identifier)
        if characteristic is None or not isinstance(value, bytes) or len(value) > 512:
            raise ValueError("invalid actual notification")
        self._notifications.put_nowait((characteristic, bytes(value)))

    async def _deliver_notifications(self):
        while True:
            characteristic, value = await self._notifications.get()
            await self.device.notify_subscribers(characteristic, value=value)
            # Indications wait for the native guest's confirmation. Keep the
            # stream reader free so that confirmation can actually be received.
            await asyncio.wait_for(self.device.indicate_subscribers(characteristic, value=value), 20)

    def close(self):
        if self._closed is None:
            return
        callback, self._closed = self._closed, None
        for task in tuple(self._tasks):
            task.cancel()
        self.link.close()
        if hasattr(self, "controller"):
            self.controller.le_connections.clear()
        callback()
