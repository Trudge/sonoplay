# SPDX-License-Identifier: GPL-3.0-or-later
#
# Original work Copyright (C) 2021 songchenwen
# Modified work Copyright (C) 2025 plexdlnaplayer-enhanced contributors
#
# This file is part of plexdlnaplayer-enhanced, a fork of plexdlnaplayer.
# Original project: https://github.com/songchenwen/plexdlnaplayer
#
# Modifications from original:
#   - Added atomic JSON writes to prevent data corruption
#   - Added device statistics persistence (play count, duration)
#   - Added onboarding state management
#   - Added device status tracking (online/offline)
#   - Integrated DataStore abstraction layer
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

from pydantic_settings import BaseSettings
from pathlib import Path
from datetime import datetime, timezone
import json
import logging
import os
import threading

logger = logging.getLogger(__name__)

# Lock for thread-safe read-modify-write on data file
_data_lock = threading.RLock()


def _private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        logger.warning("Unable to restrict permissions on config directory %s", path)


def atomic_write_json(path: Path, data: dict, fsync: bool = True) -> None:
    """Atomically write JSON with owner-only permissions.

    Uses a random temp file in the destination directory so another local
    principal cannot pre-create or symlink it. The final file is chmod 0600.
    """
    path = Path(path)
    _private_dir(path.parent)

    import tempfile

    fd, temp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=path.name + ".", suffix=".tmp"
    )
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w") as f:
            os.fchmod(f.fileno(), 0o600)
            json.dump(data, f, indent=4)
            f.flush()
            if fsync:
                os.fsync(f.fileno())
        os.replace(temp_path, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            temp_path.unlink()
        except OSError:
            pass
        raise


DEFAULT_STATS = {
    "play_count": 0,
    "play_duration_ms": 0,
    "status": "offline",
    "last_seen": None
}

# DataStore will be initialized after Settings instance is created
datastore = None


class Settings(BaseSettings):
    http_port: int = 32488
    host_ip: str | None = None
    product: str = "SonoPlay"
    aliases: str = ""
    location_url: str | None = None
    version: str = "1"
    platform: str = "Linux"
    platform_version: str = "1"
    client_device: str | None = None
    client_device_name: str | None = None
    client_model: str | None = None
    client_profile: str | None = None
    plex_notify_interval: float = 0.5
    config_path: str = "config"
    data_file_name: str = "data.json"
    enable_onboarding_wizard: bool = True
    # Audio transcoding thresholds - exceeding these triggers Plex transcode
    # Sonos speakers typically support up to ~320kbps for network streams
    # and max 48kHz sample rate. CD quality is 1411 kbps at 44.1kHz.
    audio_transcode_threshold_kbps: int | None = 1500  # Safe default for most DLNA
    audio_transcode_max_sample_rate_hz: int | None = 48000  # Max for Sonos/most DLNA
    
    # HTTP timeout settings (in seconds)
    http_timeout_default: float = 10.0  # Default timeout for all requests
    http_timeout_connect: float = 5.0   # Connection timeout
    http_timeout_plex_tv: float = 10.0  # Timeout for plex.tv API requests
    http_timeout_dlna: float = 10.0     # Timeout for local DLNA device requests (was 5.0, see issue #10)
    dlna_read_timeout: float = 3.0
    dlna_write_timeout: float = 5.0
    dlna_read_retries: int = 2
    
    # Subscription and polling settings
    subscriber_ttl_seconds: int = 300   # How long before idle subscribers are cleaned up
    dlna_subscribe_timeout: int = 120   # DLNA event subscription timeout
    adapter_idle_interval: int = 60     # Seconds between state checks when idle
    pin_cache_max_size: int = 100       # Maximum cached Plex PIN login entries
    # Plex-backed authentication for the local UI/API (prototype).
    # Disabled by default so existing deployments keep working unchanged.
    auth_enabled: bool = False
    auth_allowed_users: str = ""        # Comma-separated Plex user IDs/usernames
    auth_session_secret: str | None = None
    auth_session_ttl_hours: int = 24
    auth_cookie_secure: bool = False    # Set true when served over HTTPS
    auth_client_identifier: str = "sonoplay-web"
    auth_allow_any_user: bool = False
    auth_rate_limit_per_minute: int = 30
    trusted_hosts: str = ""            # Comma-separated Host allowlist
    allow_loopback_subscribers: bool = False
    # Override the PMS address used in stream URLs sent to DLNA speakers.
    # Needed when Plexamp connects to PMS via WAN/external IP (remote access mode)
    # but hairpin NAT is unavailable — speakers can't reach PMS via WAN IP.
    # Set to PMS's LAN IP (e.g. PMS_ADDRESS=192.168.1.100) to force local routing.
    pms_address: str | None = None
    pms_port: int = 32400

    def __init__(self, **values):
        super().__init__(**values)
        object.__setattr__(self, "_data_cache", None)

    def dlna_name_alias(self, uuid: str, name: str, ip: str):
        data = self.load_data()
        alias = data.get(uuid, {}).get('alias', None)
        if alias is not None:
            return alias
        if not settings.aliases:
            return name
        aliases = settings.aliases.split(",")
        for alias in aliases:
            k, v = alias.split(":")
            if k.strip() in [uuid.strip(), name.strip(), ip.strip()]:
                return v.strip()
        return name

    def save_dlna_name_alias(self, uuid, alias):
        with _data_lock:
            data = self.load_data()
            info = data.get(uuid, {})
            info['alias'] = alias
            data[uuid] = info
            self.save_data(data)

    def load_data(self):
        with _data_lock:
            cache = getattr(self, "_data_cache", None)
            if cache is not None:
                return cache
            p = Path(self.config_path).joinpath(self.data_file_name)
            _private_dir(p.parent)
            if not p.exists():
                object.__setattr__(self, "_data_cache", {})
                return self._data_cache
            try:
                os.chmod(p, 0o600)
            except OSError:
                pass
            try:
                with open(p) as f:
                    j = json.load(f)
                    object.__setattr__(self, "_data_cache", j)
                    return self._data_cache
            except Exception:
                object.__setattr__(self, "_data_cache", {})
                return self._data_cache

    def save_data(self, data, fsync: bool = True):
        with _data_lock:
            p = Path(self.config_path).joinpath(self.data_file_name)
            atomic_write_json(p, data, fsync=fsync)
            object.__setattr__(self, "_data_cache", data)

    def get_token_for_uuid(self, uuid):
        d = self.load_data()
        return d.get(uuid, {}).get("token", None)

    def set_token_for_uuid(self, uuid, token):
        with _data_lock:
            d = self.load_data()
            info = d.get(uuid, {})
            info['token'] = token
            d[uuid] = info
            self.save_data(d)

    def get_device_stats(self, uuid):
        data = self.load_data()
        info = data.get(uuid, {})
        stats = info.get("stats", {})
        merged = DEFAULT_STATS.copy()
        merged.update(stats)
        return merged

    def _mutate_device_stats(self, uuid, mutator):
        with _data_lock:
            # Bypass cache to get fresh data under lock
            object.__setattr__(self, "_data_cache", None)
            data = self.load_data()
            info = data.get(uuid, {})
            stats = info.get("stats", {})
            merged = DEFAULT_STATS.copy()
            merged.update(stats)
            mutator(merged)
            info['stats'] = merged
            data[uuid] = info
            self.save_data(data, fsync=False)

    def update_device_stats(self, uuid, **kwargs):
        def mutator(stats):
            for key, value in kwargs.items():
                if isinstance(value, datetime):
                    value = value.isoformat()
                stats[key] = value
        self._mutate_device_stats(uuid, mutator)

    def increment_play_count(self, uuid):
        def mutator(stats):
            stats['play_count'] = stats.get('play_count', 0) + 1
            stats['status'] = 'playing'
            stats['last_seen'] = datetime.now(timezone.utc).isoformat()
        self._mutate_device_stats(uuid, mutator)

    def add_play_duration_ms(self, uuid, delta_ms):
        def mutator(stats):
            stats['play_duration_ms'] = stats.get('play_duration_ms', 0) + max(0, int(delta_ms))
            stats['last_seen'] = datetime.now(timezone.utc).isoformat()
        self._mutate_device_stats(uuid, mutator)

    def mark_device_status(self, uuid, status):
        self.update_device_stats(uuid, status=status, last_seen=datetime.now(timezone.utc))


settings = Settings()

# Initialize DataStore with settings instance
from settings.datastore import JSONDataStore
datastore = JSONDataStore(settings)
object.__setattr__(settings, "datastore", datastore)
