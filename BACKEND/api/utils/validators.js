import IPCIDR from "ip-cidr";

// EN: Default authorized target ranges. Adjust for your environment.
// o.
const defaultAuthorizedTargets = [
    "192.168.10.0/24",
    "10.0.5.0/24"
];

// EN: RFC1918 + common local/non-routable blocks.
// es.
const localNetworkRanges = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "100.64.0.0/10"
];

function getAuthorizedTargets() {
    const raw = process.env.AUTHORIZED_TARGETS;
    if (!raw || raw.trim() === "") {
        return defaultAuthorizedTargets;
    }

    return raw
        .split(",")
        .map(value => value.trim())
        .filter(Boolean);
}

// EN: Validate IPv4 target format.
// ES: Validar formato de IP objetivo IPv4.
export function validateTarget(target) {
    const ipRegex =
        /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}$/;

    return ipRegex.test(target);
}

// EN: Validate CIDR subnet format.
// ES: Validar formato de subred CIDR.
export function validateSubnet(subnet) {
    // EN/ES: Example formato/format: 192.168.1.0/24
    const cidrRegex =
        /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}\/(2[0-9]|3[0-2]|[1][0-9]|[0-9])$/;

    return cidrRegex.test(subnet);
}

// EN: Check whether a target IP is within allowed CIDR ranges.
// gos CIDR permitidos.
export function isAuthorizedTarget(ip) {
    return getAuthorizedTargets().some(targetRule => {
        if (targetRule === "*") {
            return true;
        }
        // AUTHORIZED_TARGETS.
        if (!targetRule.includes("/")) {
            return targetRule === ip;
        }

        try {
            const cidr = new IPCIDR(targetRule);
            return cidr.contains(ip);
        } catch {
            return false;
        }
    });
}

// EN: Determine if target belongs to a public WAN range.
// go publico WAN.
export function isPublicTarget(ip) {
    if (!validateTarget(ip)) {
        return false;
    }

    const isLocal = localNetworkRanges.some(range => {
        const cidr = new IPCIDR(range);
        return cidr.contains(ip);
    });

    return !isLocal;
}
