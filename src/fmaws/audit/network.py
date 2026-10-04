"""Security groups open to the internet on administrative or database ports."""

from typing import Any

from fmaws.audit.base import AuditContext, AuditDenied, register
from fmaws.audit.findings import make
from fmaws.models.finding import Finding, Severity
from fmaws.models.requirement import Confidence

SENSITIVE_PORTS = {
    22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 1433: "SQL Server",
    1521: "Oracle", 27017: "MongoDB", 9200: "Elasticsearch", 11211: "Memcached",
}  # fmt: skip
_ANYWHERE = ("0.0.0.0/0", "::/0")


def _public_tcp_ranges(group: dict[str, Any]) -> list[tuple[int, int]]:
    """TCP port ranges (inclusive) that the group accepts from anywhere on the internet."""
    ranges: list[tuple[int, int]] = []
    for rule in group.get("IpPermissions", []):
        sources = [r.get("CidrIp") for r in rule.get("IpRanges", [])]
        sources += [r.get("CidrIpv6") for r in rule.get("Ipv6Ranges", [])]
        if not any(source in _ANYWHERE for source in sources):
            continue
        protocol = str(rule.get("IpProtocol"))
        if protocol == "-1":
            ranges.append((0, 65535))
        elif protocol in ("tcp", "6"):
            ranges.append((rule.get("FromPort", 0), rule.get("ToPort", 65535)))
    return ranges


def port_open(group: dict[str, Any], port: int) -> bool:
    return any(low <= port <= high for low, high in _public_tcp_ranges(group))


def world_open(group: dict[str, Any]) -> tuple[bool, set[int]]:
    """(all ports open to the internet, sensitive ports open to the internet)."""
    ranges = _public_tcp_ranges(group)
    everything = any(low <= 1 and high >= 65535 for low, high in ranges)
    ports = {p for p in SENSITIVE_PORTS for low, high in ranges if low <= p <= high}
    return everything, ports


class Network:
    name = "network"
    regional = True

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        groups = ctx.pages("ec2", "describe_security_groups", "SecurityGroups", region)
        attached: set[str] | None
        try:
            interfaces = ctx.pages(
                "ec2", "describe_network_interfaces", "NetworkInterfaces", region
            )
            attached = {g["GroupId"] for eni in interfaces for g in eni.get("Groups", [])}
        except AuditDenied as exc:
            ctx.denied[exc.permission] += 1
            attached = None  # unknown: assume in use, with lower confidence

        findings: list[Finding] = []
        for group in groups:
            everything, ports = world_open(group)
            if not everything and not ports:
                continue
            group_id = group["GroupId"]
            arn = f"arn:{ctx.partition}:ec2:{region}:{ctx.account}:security-group/{group_id}"
            in_use = attached is None or group_id in attached
            usage = "" if in_use else " The group is not attached to any network interface."
            confidence = Confidence.MEDIUM if attached is None else Confidence.HIGH
            label = f"{group.get('GroupName', group_id)} ({group_id})"
            if everything:
                findings.append(
                    make(
                        "SG_OPEN_ALL_PORTS",
                        arn,
                        f"{label} allows all ports from 0.0.0.0/0 or ::/0.{usage}",
                        severity=None if in_use else Severity.MEDIUM,
                        confidence=confidence,
                    )  # fmt: skip
                )
            else:
                names = ", ".join(f"{p} ({SENSITIVE_PORTS[p]})" for p in sorted(ports))
                findings.append(
                    make(
                        "SG_OPEN_SENSITIVE_PORT",
                        arn,
                        f"{label} allows {names} from 0.0.0.0/0 or ::/0.{usage}",
                        severity=None if in_use else Severity.LOW,
                        evidence={"ports": sorted(ports)},
                        confidence=confidence,
                    )  # fmt: skip
                )
        return findings


register(Network())
