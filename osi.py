from __future__ import annotations

from dataclasses import dataclass

OSI_LAYER_MAP = {
    7: "Application",
    6: "Presentation",
    5: "Session",
    4: "Transport",
    3: "Network",
    2: "Data Link",
    1: "Physical",
}

PORT_PROTOCOL = {
    20: "FTP",
    21: "FTP",
    22: "SSH",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
}


def infer_osi_layer(event: dict) -> int:
    if any(k in event for k in ("http_method", "url", "user_agent", "application_payload")):
        return 7
    if any(k in event for k in ("session_id", "auth_token", "ssh_banner")):
        return 5
    if any(k in event for k in ("src_port", "dst_port", "tcp_flags", "udp_len")):
        return 4
    if any(k in event for k in ("src_ip", "dst_ip", "ttl", "route_hop")):
        return 3
    if any(k in event for k in ("src_mac", "dst_mac", "ether_type")):
        return 2
    return 1


def layer_name(layer: int) -> str:
    return OSI_LAYER_MAP.get(layer, "Unknown")


def validate_event(event: dict) -> bool:
    layer = infer_osi_layer(event)
    if layer == 7 and event.get("http_method") == "" and not event.get("url"):
        return False
    if layer == 4:
        port = event.get("dst_port") or event.get("src_port")
        if port is not None and not (0 < int(port) < 65536):
            return False
    return True


def osi_summary(event: dict) -> dict:
    layer = infer_osi_layer(event)
    return {
        "layer": layer,
        "layer_name": layer_name(layer),
        "valid": validate_event(event),
        "protocol_hint": PORT_PROTOCOL.get(event.get("dst_port") or event.get("src_port")),
    }
