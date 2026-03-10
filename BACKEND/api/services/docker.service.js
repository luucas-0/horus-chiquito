import { exec } from "child_process";
import { parseStringPromise } from "xml2js";
import { networkInterfaces } from "os";
import IPCIDR from "ip-cidr";

// EN: Core scanning service (network discovery, deep Nmap scan, Hydra checks).
// es Hydra).

// EN: Services that can be tested by Hydra credential checks.
// ser verificados por Hydra.
const hydraTargets = {
    "22": "ssh",
    "21": "ftp",
    "23": "telnet",
    "3389": "rdp",
    "445": "smb",
    "3306": "mysql",
    "5432": "postgres",
    "1433": "mssql"
};

// EN: Scanner container image and optional Docker network override.
// al para laboratorio.
function getScannerDockerImage() {
    return process.env.KALI_CONTAINER || "kali-redteam";
}
function getScannerDockerNetwork() {
    return (process.env.SCANNER_DOCKER_NETWORK || "").trim();
}

const hydraServiceCooldowns = new Map();
const hydraHostCooldowns = new Map();

// EN: Output patterns used to detect defensive controls in target services.
// servicios objetivo.
const hydraLockoutPatterns = [
    /account\s+(?:is\s+)?locked/i,
    /locked\s+out/i,
    /too\s+many\s+failed\s+logins?/i,
    /too\s+many\s+authentication\s+failures/i,
    /authentication\s+blocked/i
];

const hydraRateLimitPatterns = [
    /rate\s*limit/i,
    /too\s+many\s+requests/i,
    /retry\s+later/i,
    /slow\s*down/i,
    /throttl/i
];

const scanProfileDefaults = {
    fast: {
        nmap_discovery_timeout_sec: 90,
        nmap_discovery_host_timeout_sec: 12,
        nmap_discovery_max_retries: 1,
        nmap_discovery_min_hostgroup: 32,
        nmap_discovery_min_parallelism: 32,
        nmap_deep_probe_top_ports: 200,
        nmap_deep_probe_host_timeout_sec: 18,
        nmap_deep_detail_host_timeout_sec: 45,
        nmap_deep_timeout_sec: 180,
        nmap_max_retries: 1,
        nmap_script_timeout_sec: 20,
        nmap_enable_os_detection: false,
        nmap_enable_traceroute: false,
        nmap_version_intensity: "light",
        hydra_max_attempts_cap: 12,
        hydra_max_duration_sec_cap: 20,
        hydra_tasks_cap: 4,
        hydra_max_services_per_scan_cap: 2
    },
    balanced: {
        nmap_discovery_timeout_sec: 140,
        nmap_discovery_host_timeout_sec: 18,
        nmap_discovery_max_retries: 1,
        nmap_discovery_min_hostgroup: 24,
        nmap_discovery_min_parallelism: 24,
        nmap_deep_probe_top_ports: 500,
        nmap_deep_probe_host_timeout_sec: 24,
        nmap_deep_detail_host_timeout_sec: 75,
        nmap_deep_timeout_sec: 300,
        nmap_max_retries: 1,
        nmap_script_timeout_sec: 30,
        nmap_enable_os_detection: false,
        nmap_enable_traceroute: false,
        nmap_version_intensity: "light",
        hydra_max_attempts_cap: 24,
        hydra_max_duration_sec_cap: 35,
        hydra_tasks_cap: 4,
        hydra_max_services_per_scan_cap: 3
    },
    full: {
        nmap_discovery_timeout_sec: 240,
        nmap_discovery_host_timeout_sec: 25,
        nmap_discovery_max_retries: 2,
        nmap_discovery_min_hostgroup: 16,
        nmap_discovery_min_parallelism: 16,
        nmap_deep_probe_top_ports: 1000,
        nmap_deep_probe_host_timeout_sec: 35,
        nmap_deep_detail_host_timeout_sec: 150,
        nmap_deep_timeout_sec: 600,
        nmap_max_retries: 2,
        nmap_script_timeout_sec: 45,
        nmap_enable_os_detection: true,
        nmap_enable_traceroute: true,
        nmap_version_intensity: "all",
        hydra_max_attempts_cap: 60,
        hydra_max_duration_sec_cap: 90,
        hydra_tasks_cap: 8,
        hydra_max_services_per_scan_cap: 6
    }
};

/**
 * EN: Parse and clamp integer env values.
// o.
 */
function parseIntegerEnv(name, fallback, min, max = Number.MAX_SAFE_INTEGER) {
    const raw = process.env[name];
    if (raw == null || raw === "") {
        return fallback;
    }

    const parsed = Number.parseInt(raw, 10);
    if (!Number.isFinite(parsed)) {
        return fallback;
    }

    return Math.min(Math.max(parsed, min), max);
}

/**
 * EN: Parse boolean env values with a safe fallback.
 // fallback seguro.
 */
function parseBooleanEnv(name, fallback) {
    const raw = process.env[name];
    if (raw == null || raw === "") {
        return fallback;
    }

    if (raw.toLowerCase() === "true") {
        return true;
    }

    if (raw.toLowerCase() === "false") {
        return false;
    }

    return fallback;
}

/**
 * EN: Parse enum-like env vars.
// um.
 */
function parseEnumEnv(name, allowedValues, fallback) {
    const raw = process.env[name];
    if (raw == null || raw === "") {
        return fallback;
    }

    const normalized = raw.toLowerCase();
    return allowedValues.includes(normalized) ? normalized : fallback;
}

/**
 * EN: Build effective Nmap scan policy from env vars and selected profile.
// o y perfil.
 */
function getScanPolicy() {
    const profile = parseEnumEnv("SCAN_PROFILE", ["fast", "balanced", "full"], "fast");
    const defaults = scanProfileDefaults[profile];

    const versionIntensity = parseEnumEnv(
        "NMAP_VERSION_INTENSITY",
        ["light", "all"],
        defaults.nmap_version_intensity
    );

    return {
        profile,
        nmap_discovery_timeout_sec: parseIntegerEnv(
            "NMAP_DISCOVERY_TIMEOUT_SEC",
            defaults.nmap_discovery_timeout_sec,
            30,
            1200
        ),
        nmap_discovery_host_timeout_sec: parseIntegerEnv(
            "NMAP_DISCOVERY_HOST_TIMEOUT_SEC",
            defaults.nmap_discovery_host_timeout_sec,
            5,
            300
        ),
        nmap_discovery_max_retries: parseIntegerEnv(
            "NMAP_DISCOVERY_MAX_RETRIES",
            defaults.nmap_discovery_max_retries,
            0,
            5
        ),
        nmap_discovery_min_hostgroup: parseIntegerEnv(
            "NMAP_DISCOVERY_MIN_HOSTGROUP",
            defaults.nmap_discovery_min_hostgroup,
            1,
            256
        ),
        nmap_discovery_min_parallelism: parseIntegerEnv(
            "NMAP_DISCOVERY_MIN_PARALLELISM",
            defaults.nmap_discovery_min_parallelism,
            1,
            256
        ),
        nmap_deep_probe_top_ports: parseIntegerEnv(
            "NMAP_DEEP_PROBE_TOP_PORTS",
            defaults.nmap_deep_probe_top_ports,
            20,
            1000
        ),
        nmap_deep_probe_host_timeout_sec: parseIntegerEnv(
            "NMAP_DEEP_PROBE_HOST_TIMEOUT_SEC",
            defaults.nmap_deep_probe_host_timeout_sec,
            10,
            300
        ),
        nmap_deep_detail_host_timeout_sec: parseIntegerEnv(
            "NMAP_DEEP_DETAIL_HOST_TIMEOUT_SEC",
            defaults.nmap_deep_detail_host_timeout_sec,
            15,
            600
        ),
        nmap_deep_timeout_sec: parseIntegerEnv(
            "NMAP_DEEP_TIMEOUT_SEC",
            defaults.nmap_deep_timeout_sec,
            30,
            1800
        ),
        nmap_max_retries: parseIntegerEnv(
            "NMAP_MAX_RETRIES",
            defaults.nmap_max_retries,
            0,
            5
        ),
        nmap_script_timeout_sec: parseIntegerEnv(
            "NMAP_SCRIPT_TIMEOUT_SEC",
            defaults.nmap_script_timeout_sec,
            5,
            180
        ),
        nmap_version_intensity: versionIntensity,
        nmap_enable_os_detection: parseBooleanEnv(
            "NMAP_ENABLE_OS_DETECTION",
            defaults.nmap_enable_os_detection
        ),
        nmap_enable_traceroute: parseBooleanEnv(
            "NMAP_ENABLE_TRACEROUTE",
            defaults.nmap_enable_traceroute
        ),
        hydra_caps: {
            max_attempts: defaults.hydra_max_attempts_cap,
            max_duration_sec: defaults.hydra_max_duration_sec_cap,
            tasks: defaults.hydra_tasks_cap,
            max_services_per_scan: defaults.hydra_max_services_per_scan_cap
        }
    };
}

/**
 * EN: Build effective Hydra execution policy from env vars.
// o.
 */
function getHydraPolicy(scanPolicy) {
    const caps = scanPolicy.hydra_caps;
    const requestedAttempts = parseIntegerEnv("HYDRA_MAX_ATTEMPTS", caps.max_attempts, 1, 10000);
    const requestedDuration = parseIntegerEnv("HYDRA_MAX_DURATION_SEC", caps.max_duration_sec, 5, 3600);
    const requestedTasks = parseIntegerEnv("HYDRA_TASKS", caps.tasks, 1, 16);
    const requestedMaxServices = parseIntegerEnv(
        "HYDRA_MAX_SERVICES_PER_SCAN",
        caps.max_services_per_scan,
        1,
        32
    );

    return {
        enabled: parseBooleanEnv("HYDRA_ENABLED", true),
        max_attempts: Math.min(requestedAttempts, caps.max_attempts),
        max_duration_sec: Math.min(requestedDuration, caps.max_duration_sec),
        cooldown_sec: parseIntegerEnv("HYDRA_COOLDOWN_SEC", 120, 0, 86400),
        tasks: Math.min(requestedTasks, caps.tasks),
        max_services_per_scan: Math.min(requestedMaxServices, caps.max_services_per_scan),
        stop_on_lockout: parseBooleanEnv("HYDRA_STOP_ON_LOCKOUT", true),
        stop_on_rate_limit: parseBooleanEnv("HYDRA_STOP_ON_RATE_LIMIT", true)
    };
}

/**
 * EN: Infer lockout/rate-limit signals from Hydra output.
// ales de lockout/rate-limit desde la salida de Hydra.
 */
function detectHydraDefenseSignals(rawOutput) {
    const output = (rawOutput || "").toLowerCase();
    const lockoutDetected = hydraLockoutPatterns.some(pattern => pattern.test(output));
    const rateLimited = hydraRateLimitPatterns.some(pattern => pattern.test(output));
    return { lockoutDetected, rateLimited };
}

/**
 * EN: Extract a compact, UI-friendly output summary.
 // compacto y util para la UI.
 */
function summarizeHydraOutput(rawOutput) {
    if (!rawOutput) {
        return "";
    }

    return rawOutput
        .split("\n")
        .filter(line => /\[|login:|password:|lock|limit|throttl|retry|error/i.test(line))
        .join("\n")
        .substring(0, 400);
}

/**
 * EN: Compute network and broadcast addresses from CIDR.
 // CIDR.
 */
function getSubnetBoundaries(subnet) {
    try {
        const cidr = new IPCIDR(subnet);
        const [networkAddress, broadcastAddress] = cidr.toRange();
        return { networkAddress, broadcastAddress };
    } catch {
        return { networkAddress: null, broadcastAddress: null };
    }
}

/**
 * EN: Check if a discovery reason is usually ambiguous/noisy.
// to suele ser ambigua/ruidosa.
 */
function isResetLikeReason(reason) {
    return reason === "reset" || reason === "conn-refused";
}

/**
 * EN: Read ARP cache and map IP -> MAC from the host OS.
 * ES: Leer cache ARP y mapear IP -> MAC desde el sistema host.
 */
async function getArpMacByIp() {
    return new Promise((resolve) => {
        exec("arp -an", { timeout: 5000, maxBuffer: 1024 * 1024 }, (error, stdout) => {
            if (error || !stdout) {
                return resolve(new Map());
            }

            const map = new Map();
            for (const line of stdout.split("\n")) {
                const match = line.match(/\(([^)]+)\)\s+at\s+([0-9a-f:]+|\(incomplete\))/i);
                if (!match) {
                    continue;
                }

                const ip = match[1];
                const mac = match[2].toLowerCase();
                if (mac === "(incomplete)") {
                    continue;
                }

                map.set(ip, mac);
            }

            resolve(map);
        });
    });
}

/**
 * EN: Detect local IPv4 interfaces and derive their CIDR subnet.
// terfaces IPv4 locales y derivar su subred CIDR.
 */
export function detectLocalNetwork() {
    const interfaces = networkInterfaces();
    const results = [];

    for (const [name, addrs] of Object.entries(interfaces)) {
        for (const addr of addrs) {
            if (addr.family === "IPv4" && !addr.internal) {
                // EN: Derive CIDR from netmask.
                // ES: Derivar CIDR desde la mascara de red.
                const maskParts = addr.netmask.split(".").map(Number);
                const cidr = maskParts.reduce((acc, octet) => acc + (octet >>> 0).toString(2).replace(/0/g, "").length, 0);

                // EN: Compute network address (IP AND netmask).
                // de red (IP AND mascara).
                const ipParts = addr.address.split(".").map(Number);
                const netParts = ipParts.map((p, i) => p & maskParts[i]);
                const network = netParts.join(".");

                results.push({
                    interface: name,
                    ip: addr.address,
                    netmask: addr.netmask,
                    subnet: cidr < 24 ? `${network}/${cidr}` : `${network}/${cidr}`,
                    // Provide a capped /24 subnet for safe scanning when detected range is too large
                    scan_subnet: cidr < 24 ? `${ipParts.slice(0, 3).join('.')}.0/24` : `${network}/${cidr}`,
                    mac: addr.mac || null
                });
            }
        }
    }

    return results;
}

/**
 * EN: Discover active hosts in a subnet using Nmap XML output.
// do salida XML de Nmap.
 */
function execCommandWithOutput(command, options) {
    return new Promise((resolve, reject) => {
        exec(command, options, (error, stdout, stderr) => {
            if (error) {
                error.stdout = stdout;
                error.stderr = stderr;
                return reject(error);
            }
            resolve({ stdout, stderr });
        });
    });
}

function extractNmapElapsed(parsed) {
    return parsed?.nmaprun?.runstats?.[0]?.finished?.[0]?.$.elapsed || "0";
}

function extractOpenPortIds(host) {
    const ports = host?.ports?.[0]?.port || [];
    return [...new Set(ports
        .filter(p => p?.state?.[0]?.$?.state === "open")
        .map(p => p?.$?.portid)
        .filter(Boolean))]
        .sort((a, b) => Number.parseInt(a, 10) - Number.parseInt(b, 10));
}

export async function discoverHosts(subnet) {
    const scanPolicy = getScanPolicy();
    const nmapArgs = [
        "-sn",
        "-n",
        "-PR",
        "-T4",
        `--max-retries ${scanPolicy.nmap_discovery_max_retries}`,
        `--min-hostgroup ${scanPolicy.nmap_discovery_min_hostgroup}`,
        `--min-parallelism ${scanPolicy.nmap_discovery_min_parallelism}`,
        `--host-timeout ${scanPolicy.nmap_discovery_host_timeout_sec}s`,
        "--reason",
        "-oX -"
    ].join(" ");

    const nmapCommandDisplay = `nmap ${nmapArgs} ${subnet}`;
    const dockerNetwork = getScannerDockerNetwork();
    const dockerImage = getScannerDockerImage();
    const discoveryNetworkFlags = dockerNetwork
        ? `--network=${dockerNetwork}`
        : "--net=host --cap-add=NET_RAW --cap-add=NET_ADMIN";
    const cmd = `docker run --rm --memory="512m" --cpus="1" ${discoveryNetworkFlags} ${dockerImage} nmap ${nmapArgs} ${subnet}`;

    let stdout = "";
    try {
        const result = await execCommandWithOutput(cmd, {
            timeout: scanPolicy.nmap_discovery_timeout_sec * 1000,
            maxBuffer: 10 * 1024 * 1024
        });
        stdout = result.stdout;
    } catch (error) {
        console.error(`[DISCOVERY ERROR] Command failed: ${error.message}`);
        console.error(`[DISCOVERY STDERR] ${error.stderr || "No stderr output"}`);
        throw new Error(`Network discovery failed: ${error.message}`);
    }

    try {
        const parsed = await parseStringPromise(stdout);
        const hosts = Array.isArray(parsed.nmaprun?.host) ? parsed.nmaprun.host : [];
        const { networkAddress, broadcastAddress } = getSubnetBoundaries(subnet);
        const warnings = [];

        const rawDevices = hosts
            .filter(h => h?.status?.[0]?.$?.state === "up")
            .map(h => {
                const addresses = Array.isArray(h.address) ? h.address : [];
                const ipv4 = addresses.find(a => a?.$?.addrtype === "ipv4");
                const macAddr = addresses.find(a => a?.$?.addrtype === "mac");
                const hostname = h.hostnames?.[0]?.hostname?.[0]?.$?.name ?? null;
                const reason = h?.status?.[0]?.$?.reason ?? null;

                return {
                    ip: ipv4?.$?.addr ?? null,
                    mac: macAddr?.$?.addr ?? null,
                    vendor: macAddr?.$?.vendor ?? null,
                    hostname,
                    reason
                };
            })
            .filter(device => Boolean(device.ip));

        let devices = rawDevices.filter(device => {
            if (!device.ip) {
                return false;
            }

            // EN: Skip network/broadcast addresses to reduce obvious noise.
            // te.
            if (networkAddress && device.ip === networkAddress) {
                return false;
            }

            if (broadcastAddress && device.ip === broadcastAddress) {
                return false;
            }

            return true;
        });

        const arpMacByIp = await getArpMacByIp();
        devices = devices.map(device => {
            const arpMac = arpMacByIp.get(device.ip);
            if (arpMac && !device.mac) {
                return { ...device, mac: arpMac };
            }
            return device;
        });

        // EN: In tethering/NAT setups (e.g. mobile hotspot), gateways may answer
        // EN: with many reset-like responses that look like fake "up" hosts.
        // der
        // hosts "up" falsos.
        const resetLikeCount = devices.filter(d => isResetLikeReason(d.reason)).length;
        const unresolvedCount = devices.filter(d => !d.mac && !d.hostname).length;
        const likelyProxyResponses = devices.length >= 4
            && resetLikeCount / devices.length >= 0.75
            && unresolvedCount / devices.length >= 0.75;

        if (likelyProxyResponses) {
            const filteredDevices = devices.filter(d => !isResetLikeReason(d.reason));
            if (filteredDevices.length !== devices.length) {
                warnings.push("Posible red con NAT/proxy (como hotspot movil): respuestas RST masivas filtradas para reducir falsos positivos.");
                devices = filteredDevices;
            }
        }

        const stats = parsed.nmaprun?.runstats?.[0]?.hosts?.[0]?.$;
        const scanInfo = parsed.nmaprun?.$;
        const elapsed = extractNmapElapsed(parsed);
        const rawHostsUp = Number.parseInt(stats?.up ?? "0", 10) || rawDevices.length;
        const hostsTotal = Number.parseInt(stats?.total ?? "0", 10);

        if (rawHostsUp > devices.length) {
            warnings.push(`Nmap reporto ${rawHostsUp} hosts activos, pero tras filtrar respuestas ambiguas quedaron ${devices.length}.`);
        }

        return {
            subnet,
            hosts_up: devices.length,
            raw_hosts_up: rawHostsUp,
            hosts_total: Number.isNaN(hostsTotal) ? 0 : hostsTotal,
            scan_time: elapsed,
            scan_profile: scanPolicy.profile,
            nmap_command: nmapCommandDisplay,
            nmap_version: scanInfo?.version || "unknown",
            warnings,
            devices
        };
    } catch (parseError) {
        throw new Error(`Failed to parse discovery results: ${parseError.message}`);
    }
}

/**
 * EN: Run deep host scan and optional Hydra credential checks.
 * EN: Includes service/version detection, scripts, OS guesses, and traceroute.
// ales.
, scripts, OS y traceroute.
 */
export async function runDeepScan(target) {
    const scanPolicy = getScanPolicy();

    // EN: Two-phase strategy: fast probe first, rich detail only on open ports.
    // puertos abiertos.
    const probeArgs = [
        "-Pn",
        "-n",
        "-T4",
        "--open",
        `--top-ports ${scanPolicy.nmap_deep_probe_top_ports}`,
        `--max-retries ${scanPolicy.nmap_max_retries}`,
        `--host-timeout ${scanPolicy.nmap_deep_probe_host_timeout_sec}s`,
        "--reason",
        "-oX -"
    ].join(" ");
    const dockerNetwork = getScannerDockerNetwork();
    const dockerImage = getScannerDockerImage();
    const runtimeNetworkFlag = dockerNetwork ? ` --network=${dockerNetwork}` : "";
    const probeCommand = `docker run --rm --memory="1g" --cpus="2"${runtimeNetworkFlag} ${dockerImage} nmap ${probeArgs} ${target}`;
    const probeCommandDisplay = `nmap ${probeArgs} ${target}`;

    let probeStdout = "";
    try {
        const probeResult = await execCommandWithOutput(probeCommand, {
            timeout: Math.min(scanPolicy.nmap_deep_timeout_sec * 1000, 120000),
            maxBuffer: 10 * 1024 * 1024
        });
        probeStdout = probeResult.stdout;
    } catch (error) {
        console.error(`[NMAP PROBE ERROR] Command failed: ${error.message}`);
        console.error(`[NMAP PROBE STDERR] ${error.stderr || "No stderr output"}`);
        throw new Error(`Nmap deep probe failed: ${error.message}`);
    }

    let probeParsed;
    try {
        probeParsed = await parseStringPromise(probeStdout);
    } catch (parseError) {
        console.error(`[NMAP PROBE PARSE ERROR] ${parseError.message}`);
        console.error(`[NMAP PROBE RAW OUTPUT] ${probeStdout.substring(0, 1000)}...`);
        throw new Error(`Failed to parse deep probe results: ${parseError.message}`);
    }

    const probeHost = probeParsed.nmaprun?.host?.[0];
    const probeNmapVersion = probeParsed.nmaprun?.$?.version || "unknown";
    const probeElapsed = extractNmapElapsed(probeParsed);

    if (!probeHost || probeHost.status?.[0]?.$?.state !== "up") {
        return {
            host: target,
            status: "down",
            scan_profile: scanPolicy.profile,
            scan_strategy: "two_phase_fast",
            nmap_command: probeCommandDisplay,
            nmap_version: probeNmapVersion,
            scan_time: probeElapsed,
            network_info: {},
            ports: [],
            os_detection: null,
            traceroute: [],
            scripts: [],
            host_scripts: [],
            vulnerabilities: [],
            credential_tests: [],
            hydra_commands: []
        };
    }

    const probeOpenPorts = extractOpenPortIds(probeHost);
    const versionFlag = scanPolicy.nmap_version_intensity === "all" ? "--version-all" : "--version-light";
    const detailArgParts = [
        "-Pn",
        "-n",
        "-sV",
        versionFlag,
        "-sC",
        `-p ${probeOpenPorts.join(",")}`,
        `--max-retries ${scanPolicy.nmap_max_retries}`,
        `--host-timeout ${scanPolicy.nmap_deep_detail_host_timeout_sec}s`,
        `--script-timeout ${scanPolicy.nmap_script_timeout_sec}s`,
        "--reason"
    ];

    if (scanPolicy.nmap_enable_os_detection) {
        detailArgParts.push("--osscan-limit", "-O", "--osscan-guess");
    }
    if (scanPolicy.nmap_enable_traceroute) {
        detailArgParts.push("--traceroute");
    }
    detailArgParts.push("-oX -");

    const detailArgs = detailArgParts.join(" ");
    const detailCommand = `docker run --rm --memory="1g" --cpus="2"${runtimeNetworkFlag} ${dockerImage} nmap ${detailArgs} ${target}`;
    const detailCommandDisplay = `nmap ${detailArgs} ${target}`;
    const nmapCommandDisplay = `FAST_PROBE: ${probeCommandDisplay}\nDEEP_DETAIL: ${detailCommandDisplay}`;

    if (probeOpenPorts.length === 0) {
        const address = probeHost.address?.find(a => a.$.addrtype === "ipv4")?.$.addr || target;
        const hostname = probeHost.hostnames?.[0]?.hostname?.[0]?.$.name || null;
        return {
            host: address,
            hostname,
            status: probeHost.status?.[0]?.$.state || "up",
            scan_profile: scanPolicy.profile,
            scan_strategy: "two_phase_fast",
            nmap_command: probeCommandDisplay,
            nmap_version: probeNmapVersion,
            scan_time: probeElapsed,
            network_info: {
                host_ip: address,
                hostname,
                mac_address: probeHost.address?.find(a => a.$.addrtype === "mac")?.$.addr || null,
                mac_vendor: probeHost.address?.find(a => a.$.addrtype === "mac")?.$.vendor || null,
                os: null,
                all_os_matches: [],
                device_type: "unknown",
                open_ports_count: 0,
                services_detected: [],
                traceroute_hops: 0,
                vulnerabilities_count: 0
            },
            ports: [],
            os_detection: null,
            traceroute: [],
            scripts: [],
            host_scripts: [],
            vulnerabilities: [],
            credential_tests: [],
            hydra_commands: []
        };
    }

    let detailStdout = "";
    try {
        const detailResult = await execCommandWithOutput(detailCommand, {
            timeout: scanPolicy.nmap_deep_timeout_sec * 1000,
            maxBuffer: 10 * 1024 * 1024
        });
        detailStdout = detailResult.stdout;
    } catch (error) {
        console.error(`[NMAP DETAIL ERROR] Command failed: ${error.message}`);
        console.error(`[NMAP DETAIL STDERR] ${error.stderr || "No stderr output"}`);
        throw new Error(`Nmap deep detail failed: ${error.message}`);
    }

    let parsed;
    try {
        parsed = await parseStringPromise(detailStdout);
    } catch (parseError) {
        console.error(`[NMAP DETAIL PARSE ERROR] ${parseError.message}`);
        console.error(`[NMAP DETAIL RAW OUTPUT] ${detailStdout.substring(0, 1000)}...`);
        throw new Error(`Failed to parse deep detail results: ${parseError.message}`);
    }

    const host = parsed.nmaprun?.host?.[0];
    const nmapVersion = parsed.nmaprun?.$?.version || probeNmapVersion;
    const detailElapsed = extractNmapElapsed(parsed);
    const elapsedTotalSeconds = (Number.parseFloat(probeElapsed) || 0) + (Number.parseFloat(detailElapsed) || 0);
    const elapsed = elapsedTotalSeconds > 0 ? elapsedTotalSeconds.toFixed(2) : detailElapsed;

    if (!host) {
        return {
            host: target,
            status: "down",
            scan_profile: scanPolicy.profile,
            scan_strategy: "two_phase_fast",
            nmap_command: nmapCommandDisplay,
            nmap_version: nmapVersion,
            scan_time: elapsed,
            network_info: {},
            ports: [],
            os_detection: null,
            traceroute: [],
            scripts: [],
            host_scripts: [],
            vulnerabilities: [],
            credential_tests: [],
            hydra_commands: []
        };
    }
    // ame.
    const address = host.address?.find(a => a.$.addrtype === "ipv4")?.$.addr || target;
    const macAddr = host.address?.find(a => a.$.addrtype === "mac");
    const hostname = host.hostnames?.[0]?.hostname?.[0]?.$.name || null;
    const hostState = host.status?.[0]?.$.state || "unknown";
    // de sistema operativo.
    const osMatches = host.os?.[0]?.osmatch?.map(om => ({
        name: om.$.name,
        accuracy: Number.parseInt(om.$.accuracy, 10),
        os_family: om.osclass?.[0]?.$.osfamily || null,
        os_gen: om.osclass?.[0]?.$.osgen || null,
        type: om.osclass?.[0]?.$.type || null,
        vendor: om.osclass?.[0]?.$.vendor || null,
        cpe: om.osclass?.[0]?.cpe?.[0] || null
    })) || [];
    const bestOS = osMatches.length > 0 ? osMatches[0] : null;
    // ormalizado.
    const ports = host.ports?.[0]?.port?.map(p => {
        const svc = p.service?.[0]?.$;
        const scripts = p.script?.map(s => ({
            id: s.$.id,
            output: s.$.output || s._ || ""
        })) || [];

        return {
            port: p.$.portid,
            protocol: p.$.protocol || "tcp",
            state: p.state?.[0]?.$.state,
            reason: p.state?.[0]?.$.reason || null,
            service: svc?.name || null,
            product: svc?.product || null,
            version: svc?.version || null,
            extra_info: svc?.extrainfo || null,
            os_type: svc?.ostype || null,
            device_type: svc?.devicetype || null,
            cpe: p.service?.[0]?.cpe?.[0] || null,
            scripts
        };
    }) || [];

    // EN/ES: Traceroute hops / Saltos de traceroute.
    const traceroute = host.trace?.[0]?.hop?.map(h => ({
        ttl: h.$.ttl,
        ip: h.$.ipaddr || null,
        hostname: h.$.host || null,
        rtt: h.$.rtt || null
    })) || [];
    // ).
    const hostScripts = host.hostscript?.[0]?.script?.map(s => ({
        id: s.$.id,
        output: s.$.output || s._ || ""
    })) || [];
    // als from script output.
    // erabilidad desde scripts.
    const vulnerabilities = [];
    const allScripts = [...hostScripts];
    ports.forEach(p => allScripts.push(...p.scripts));
    for (const script of allScripts) {
        if (script.id.includes("vuln") || script.output.toLowerCase().includes("vulnerable")) {
            vulnerabilities.push({
                script_id: script.id,
                output: script.output.substring(0, 500),
                severity: script.output.toLowerCase().includes("critical") ? "critical" :
                    script.output.toLowerCase().includes("high") ? "high" : "medium"
            });
        }
    }
    // auth services.
    // abiertos y soportados.
    const openPorts = ports.filter(p => p.state === "open");
    const hydraResults = [];
    const hydraCommands = [];
    const hydraPolicy = getHydraPolicy(scanPolicy);
    const hostCooldownState = hydraHostCooldowns.get(target);
    let hydraAutoStopReason = null;

    if (hostCooldownState?.until > Date.now()) {
        const remaining = Math.ceil((hostCooldownState.until - Date.now()) / 1000);
        hydraAutoStopReason = `host_cooldown_active (${remaining}s restantes)`;
    }

    const hydraCandidates = openPorts.filter(p => hydraTargets[p.port]);
    if (!hydraPolicy.enabled) {
        hydraCandidates.forEach(p => {
            hydraResults.push({
                port: p.port,
                service: hydraTargets[p.port],
                status: "skipped_disabled",
                risk_score: 1,
                details: null,
                output_summary: "Hydra deshabilitado por politica"
            });
        });
    } else {
        const hydraQueue = hydraCandidates.slice(0, hydraPolicy.max_services_per_scan);
        const skippedByLimit = hydraCandidates.slice(hydraPolicy.max_services_per_scan);

        skippedByLimit.forEach(p => {
            hydraResults.push({
                port: p.port,
                service: hydraTargets[p.port],
                status: "skipped_service_limit",
                risk_score: 1,
                details: null,
                output_summary: `Limite por escaneo alcanzado (${hydraPolicy.max_services_per_scan})`
            });
        });

        for (const p of hydraQueue) {
            const proto = hydraTargets[p.port];
            const serviceKey = `${target}:${proto}:${p.port}`;
            const now = Date.now();

            if (hydraAutoStopReason) {
                hydraResults.push({
                    port: p.port,
                    service: proto,
                    status: "skipped_auto_stop",
                    risk_score: 1,
                    details: null,
                    output_summary: `Hydra detenido automaticamente: ${hydraAutoStopReason}`
                });
                continue;
            }

            const serviceCooldownUntil = hydraServiceCooldowns.get(serviceKey) || 0;
            if (serviceCooldownUntil > now) {
                const remaining = Math.ceil((serviceCooldownUntil - now) / 1000);
                hydraResults.push({
                    port: p.port,
                    service: proto,
                    status: "skipped_cooldown",
                    risk_score: 1,
                    details: null,
                    output_summary: `Cooldown activo (${remaining}s restantes)`
                });
                continue;
            }

            // EN: Generate only the first N user:password pairs for hard attempt caps.
            // tos.
            const prepPairsCmd = `awk "NR==FNR{u[++n]=\\$0;next}{for(i=1;i<=n;i++)print u[i] \\\":\\\" \\$0}" /tools/users.txt /tools/passwords.txt | head -n ${hydraPolicy.max_attempts} > /tmp/hydra_pairs.txt`;
            const hydraCmd = `hydra -C /tmp/hydra_pairs.txt ${target} ${proto} -t ${hydraPolicy.tasks} -f -I`;
            const hydraDockerCmd = `docker run --rm --memory="512m" --cpus="1"${runtimeNetworkFlag} ${dockerImage} sh -lc '${prepPairsCmd} && ${hydraCmd}'`;

            hydraCommands.push({
                port: p.port,
                service: proto,
                command: `${hydraCmd} [max_attempts=${hydraPolicy.max_attempts}, max_duration=${hydraPolicy.max_duration_sec}s, cooldown=${hydraPolicy.cooldown_sec}s]`
            });

            let hydraExecError = null;
            let hydraOutput = "";
            let hydraStderr = "";
            try {
                const hydraExec = await execCommandWithOutput(hydraDockerCmd, {
                    timeout: hydraPolicy.max_duration_sec * 1000,
                    maxBuffer: 5 * 1024 * 1024
                });
                hydraOutput = hydraExec.stdout || "";
                hydraStderr = hydraExec.stderr || "";
            } catch (error) {
                hydraExecError = error;
                hydraOutput = error.stdout || "";
                hydraStderr = error.stderr || "";
            }

            let status = "no_valid_credentials";
            let risk = 3;
            let details = null;
            const rawOutput = [hydraOutput, hydraStderr].filter(Boolean).join("\n");
            const defenseSignals = detectHydraDefenseSignals(rawOutput);
            const timedOut = Boolean(hydraExecError?.killed && hydraExecError?.signal === "SIGTERM");

            if (timedOut) {
                status = "max_duration_reached";
                risk = 2;
            } else if (rawOutput.includes("login:")) {
                status = "credentials_found";
                risk = 10;
                const match = rawOutput.match(/login:\s*(\S+)\s+password:\s*(\S+)/);
                if (match) {
                    details = { user: match[1], password: match[2] };
                }
            } else if (defenseSignals.lockoutDetected) {
                status = "lockout_detected";
                risk = 8;
                if (hydraPolicy.stop_on_lockout) {
                    hydraAutoStopReason = "lockout_detected";
                }
            } else if (defenseSignals.rateLimited) {
                status = "rate_limited";
                risk = 4;
                if (hydraPolicy.stop_on_rate_limit) {
                    hydraAutoStopReason = "rate_limited";
                }
            } else if (hydraExecError && !rawOutput.includes("0 valid password found")) {
                status = "hydra_error";
                risk = 2;
            }

            if (hydraPolicy.cooldown_sec > 0) {
                hydraServiceCooldowns.set(serviceKey, Date.now() + hydraPolicy.cooldown_sec * 1000);
            }

            if (hydraAutoStopReason && hydraPolicy.cooldown_sec > 0) {
                hydraHostCooldowns.set(target, {
                    until: Date.now() + hydraPolicy.cooldown_sec * 1000,
                    reason: hydraAutoStopReason
                });
            }

            hydraResults.push({
                port: p.port,
                service: proto,
                status,
                risk_score: risk,
                details,
                attempt_limit: hydraPolicy.max_attempts,
                max_duration_sec: hydraPolicy.max_duration_sec,
                cooldown_sec: hydraPolicy.cooldown_sec,
                output_summary: summarizeHydraOutput(rawOutput)
            });
        }
    }
    // d cards.
    // d.
    const networkInfo = {
        host_ip: address,
        hostname: hostname,
        mac_address: macAddr?.$.addr || null,
        mac_vendor: macAddr?.$.vendor || null,
        os: bestOS,
        all_os_matches: osMatches,
        device_type: bestOS?.type || openPorts.find(p => p.device_type)?.device_type || "unknown",
        open_ports_count: openPorts.length,
        services_detected: openPorts.filter(p => p.service).map(p => p.service),
        traceroute_hops: traceroute.length,
        vulnerabilities_count: vulnerabilities.length
    };

    return {
        host: address,
        hostname,
        status: hostState,
        scan_profile: scanPolicy.profile,
        scan_strategy: "two_phase_fast",
        nmap_command: nmapCommandDisplay,
        nmap_version: nmapVersion,
        scan_time: elapsed,
        network_info: networkInfo,
        ports: openPorts, // EN/ES: return open ports only / solo puertos abiertos
        os_detection: bestOS,
        traceroute,
        scripts: hostScripts,
        host_scripts: hostScripts,
        vulnerabilities,
        credential_tests: hydraResults,
        hydra_commands: hydraCommands,
        hydra_policy: hydraPolicy,
        hydra_auto_stop_reason: hydraAutoStopReason
    };
}
