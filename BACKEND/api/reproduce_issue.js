import { runDeepScan } from "./services/docker.service.js";

async function test() {
    try {
        console.log("Starting scan of 10.0.0.2...");
        const result = await runDeepScan("10.0.0.2");
        console.log("Scan Result Status:", result.status);
        if (result.status === "down") {
            console.log("Host reported DOWN. Nmap Version:", result.nmap_version);
            console.log("Nmap Command:", result.nmap_command);
        } else {
            console.log("Host reported UP.");
        }
    } catch (error) {
        console.error("Scan Error:", error);
    }
}

test();
