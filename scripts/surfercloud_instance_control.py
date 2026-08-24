#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any

API = "https://api.surfercloud.com"


def _credentials() -> tuple[str, str]:
    public_key = os.environ.get("SURFACE_SECRET_ID", "")
    private_key = os.environ.get("SURFACE_SECRET_KEY", "")
    if not public_key or not private_key:
        raise SystemExit("SURFACE_SECRET_ID and SURFACE_SECRET_KEY are required")
    return public_key, private_key


def _signature(parameters: dict[str, Any], private_key: str) -> str:
    canonical = "".join(key + str(parameters[key]) for key in sorted(parameters)) + private_key
    return hashlib.sha1(canonical.encode()).hexdigest()


def request(action: str, **parameters: Any) -> dict[str, Any]:
    public_key, private_key = _credentials()
    payload = {"Action": action, "PublicKey": public_key, **parameters}
    payload["Signature"] = _signature(payload, private_key)
    raw = json.dumps(payload, separators=(",", ":")).encode()
    http_request = urllib.request.Request(API, data=raw, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(http_request, timeout=30) as response:
            result = json.load(response)
    except (OSError, urllib.error.URLError) as exc:
        raise SystemExit(f"SurferCloud API request failed: {exc}") from exc
    if result.get("RetCode") != 0:
        raise RuntimeError(f"{action} failed: {result.get('RetCode')} {result.get('Message', '')}")
    return result


def locate_ulhost(public_ip: str) -> list[dict[str, Any]]:
    region_result = request("GetRegion")
    regions = region_result.get("Regions") or region_result.get("RegionSet") or []
    region_names = [item.get("Region") or item.get("RegionId") for item in regions if isinstance(item, dict)]
    def inspect_region(region: str) -> list[dict[str, Any]]:
        result = request("DescribeULHostInstance", Region=region, Offset=0, Limit=100)
        found = []
        for instance in result.get("ULHostInstanceSets", []):
            addresses = [item.get("IP") for item in instance.get("IPSet", [])]
            if public_ip in addresses:
                found.append({
                    "provider": "surfercloud", "product": "ULightHost", "region": region,
                    "instance_id": instance.get("ULHostId"), "name": instance.get("Name"),
                    "state": instance.get("State"), "image_id": instance.get("ImageId"),
                    "image_name": instance.get("ImageName"), "zone": instance.get("Zone"),
                    "cpu": instance.get("CPU"), "memory_mb": instance.get("Memory"),
                    "addresses": addresses,
                })
        return found

    matches = []
    with ThreadPoolExecutor(max_workers=6) as executor:
        for found in executor.map(inspect_region, filter(None, region_names)):
            matches.extend(found)
    return matches


def ulhost_state(region: str, instance_id: str) -> str | None:
    result = request("DescribeULHostInstance", Region=region, Offset=0, Limit=100)
    for instance in result.get("ULHostInstanceSets", []):
        if instance.get("ULHostId") == instance_id:
            return instance.get("State")
    return None


def stop_and_wait(match: dict[str, Any], timeout_seconds: int = 300) -> None:
    region = match["region"]
    instance_id = match["instance_id"]
    stopped_states = {"SHUTOFF", "Stopped"}
    if match.get("state") not in stopped_states:
        request("StopULHostInstance", Region=region, ULHostId=instance_id)
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        state = ulhost_state(region, instance_id)
        if state in stopped_states:
            return
        time.sleep(5)
    raise SystemExit(f"Timed out waiting for {instance_id} to reach SHUTOFF")


def resolve_available_image(match: dict[str, Any]) -> str:
    result = request(
        "DescribeImage",
        Region=match["region"],
        Zone=match["zone"],
        ImageType="Base",
        Offset=0,
        Limit=100,
    )
    candidates = [
        image
        for image in result.get("ImageSet", [])
        if image.get("ImageName") == match.get("image_name") and image.get("State") == "Available"
    ]
    if len(candidates) != 1:
        raise SystemExit(
            f"Expected one available image named {match.get('image_name')!r}, found {len(candidates)}"
        )
    return candidates[0]["ImageId"]


def main() -> None:
    parser = argparse.ArgumentParser(description="Locate or reinstall one SurferCloud ULightHost by exact public IP")
    parser.add_argument("--reset", action="store_true")
    parser.add_argument("--confirm-ip")
    args = parser.parse_args()
    target_ip = os.environ.get("SURFACE_HOST", "")
    matches = locate_ulhost(target_ip)
    if len(matches) != 1:
        sys.stdout.write(json.dumps({"target_ip": target_ip, "matches": matches}, ensure_ascii=False, indent=2) + "\n")
        raise SystemExit(2)
    if not args.reset:
        sys.stdout.write(json.dumps({"target_ip": target_ip, "matches": matches}, ensure_ascii=False, indent=2) + "\n")
        return
    if args.confirm_ip != target_ip:
        raise SystemExit("--confirm-ip must exactly match SURFACE_HOST")
    password = os.environ.get("SURFACE_PASSWORD", "")
    if not password:
        raise SystemExit("SURFACE_PASSWORD is required")
    match = matches[0]
    stop_and_wait(match)
    image_id = resolve_available_image(match)
    result = request(
        "ReinstallULHostInstance",
        Region=match["region"],
        ImageId=image_id,
        ULHostId=match["instance_id"],
        Password=base64.b64encode(password.encode()).decode(),
    )
    sys.stdout.write(json.dumps({
        "reset_requested": True,
        "instance_id": match["instance_id"],
        "region": match["region"],
        "image_id": image_id,
        "ret_code": result.get("RetCode"),
        "action": result.get("Action"),
    }, ensure_ascii=False, indent=2) + "\n")


if __name__ == "__main__":
    main()
