import asyncio
import ipaddress
import logging
import socket
import time
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

from settings import settings

SSDP_BROADCAST_PORT = 1900
SSDP_BROADCAST_ADDR = "239.255.255.250"

SSDP_SEARCH_TARGETS = [
    "ssdp:all",
    "upnp:rootdevice",
    "urn:schemas-upnp-org:device:MediaRenderer:1",
    "urn:schemas-upnp-org:service:AVTransport:1"
]


SEND_INTERVAL_SECS = 30
RECENTLY_SEEN_THROTTLE_SECS = 60  # Ignore repeat announcements within this window


def is_safe_dlna_url(url: str, base_url: str | None = None) -> bool:
    """Only allow HTTP(S) URLs pointing at a private LAN address."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return False
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        return False
    if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
        return False
    if not address.is_private:
        return False
    if base_url is not None:
        try:
            base = urlparse(base_url)
            if ipaddress.ip_address(base.hostname) != address:
                return False
        except ValueError:
            return False
    return True


def build_msearch(st: str):
    params = [
        "M-SEARCH * HTTP/1.1",
        "HOST: {0}:{1}".format(SSDP_BROADCAST_ADDR, SSDP_BROADCAST_PORT),
        "MAN: \"ssdp:discover\"",
        "MX: 2",
        f"ST: {st}",
        "",
        ""
    ]
    return "\r\n".join(params)


def guess_local_ip():
    if settings.host_ip and settings.host_ip not in ("0.0.0.0", "127.0.0.1"):
        return settings.host_ip
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "0.0.0.0"


def get_protocol(discover):

    class DlnaProtocol(object):

        def __init__(self):
            self.transport = None
            discover.protocol = self
            self.is_connected = False

        def connection_made(self, transport):
            self.transport = transport
            self.is_connected = True
            logger.info("dlna discover connected")
            asyncio.create_task(self.send_loop())

        async def send_loop(self):
            while self.is_connected:
                for st in SSDP_SEARCH_TARGETS:
                    msg = build_msearch(st)
                    self.transport.sendto(msg.encode("UTF-8"),
                                          (SSDP_BROADCAST_ADDR, SSDP_BROADCAST_PORT))
                    await asyncio.sleep(0)
                await asyncio.sleep(SEND_INTERVAL_SECS)

        def datagram_received(self, data, addr):
            try:
                info = [a.split(":", 1)
                        for a in data.decode("UTF-8").split("\r\n")[1:]]
                device = dict([(a[0].strip().lower(), a[1].strip())
                               for a in info if len(a) >= 2])
            except (UnicodeDecodeError, ValueError) as e:
                logger.debug("SSDP parse error from %s: %s", addr, e)
                return
            location = device.get('location')
            if not location:
                return
            if not is_safe_dlna_url(location):
                logger.warning("ignoring unsafe SSDP LOCATION: %s", location)
                return
            try:
                source_ip = ipaddress.ip_address(addr[0])
                location_ip = ipaddress.ip_address(urlparse(location).hostname)
                if source_ip != location_ip:
                    logger.warning("ignoring SSDP LOCATION from mismatched source: %s", location)
                    return
            except ValueError:
                return
            asyncio.create_task(discover.on_new_device(location))

        def error_received(self, exc):
            logger.error("Error received: %s", exc)

        def connection_lost(self, exc):
            logger.warning("Socket closed, stop the event loop")
            self.is_connected = False
            self.transport = None

    return DlnaProtocol


class DlnaDiscover(object):

    def __init__(self, new_device_callback):
        self.new_device_callback = new_device_callback
        self.protocol = None
        self.socket = None
        self.transport = None
        self._pending_locations = set()
        self._recently_seen_locations = {}  # location -> timestamp

    def _cleanup_recently_seen(self):
        """Remove entries older than throttle window to prevent unbounded growth."""
        now = time.time()
        expired = [loc for loc, ts in self._recently_seen_locations.items()
                   if (now - ts) >= RECENTLY_SEEN_THROTTLE_SECS * 2]
        for loc in expired:
            del self._recently_seen_locations[loc]

    async def on_new_device(self, location_url):
        if not location_url:
            return
        # Skip if currently being processed
        if location_url in self._pending_locations:
            return
        # Skip if recently seen (time-based throttle)
        now = time.time()
        last_seen = self._recently_seen_locations.get(location_url)
        if last_seen is not None and (now - last_seen) < RECENTLY_SEEN_THROTTLE_SECS:
            return
        
        # Periodic cleanup to prevent unbounded growth
        if len(self._recently_seen_locations) > 100:
            self._cleanup_recently_seen()
        
        self._pending_locations.add(location_url)
        self._recently_seen_locations[location_url] = now
        try:
            await self.new_device_callback(location_url)
        finally:
            self._pending_locations.discard(location_url)

    def init_socket(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception as e:
            logger.warning("socket reuse failed: %s", e)

        self.socket.bind(("", SSDP_BROADCAST_PORT + 10))
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)

        local_ip = guess_local_ip()
        try:
            if local_ip != "0.0.0.0":
                self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
                self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                                       socket.inet_aton(SSDP_BROADCAST_ADDR) + socket.inet_aton(local_ip))
                logger.info("dlna discover using local ip %s", local_ip)
            else:
                raise ValueError("no routable local ip detected")
        except Exception as e:
            logger.warning("dlna discover set iface failed %s: %s", local_ip, e)
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                                   socket.inet_aton(SSDP_BROADCAST_ADDR) + socket.inet_aton('0.0.0.0'))

        self.socket.setblocking(False)

    async def discover(self, loop=None):
        if settings.location_url is not None and len(settings.location_url) > 0:
            await self.on_new_device(settings.location_url)
            return
        self.init_socket()
        if loop is None:
            loop = asyncio.get_running_loop()
        self.transport, _ = await loop.create_datagram_endpoint(get_protocol(self), sock=self.socket)

    def stop(self):
        if self.transport is not None:
            try:
                self.transport.close()
            except Exception:
                pass
            self.transport = None
        if self.socket is not None:
            try:
                self.socket.close()
            except Exception:
                pass
            self.socket = None
        self.protocol = None
