/**
 * Data Normalizer - Capa de Normalizacion de Datos
 * 
 * Este modulo transforma el JSON crudo del escaneo docker.service.js
 * al formato estructurado del MER (Modelo Entidad-Relacion).
 * 
 * Simula la estructura de la base de datos sin implementar la persistencia real.
 * Cuando se integre la BD, este normalizador servira como base para los modelos.
 * 
 * IMPORTANTE: Este normalizador sigue EXACTAMENTE el esquema del MER proporcionado
 * por el equipo de base de datos (drawSQL-mysql-export-2026-02-20.sql)
 */

/**
 * Normaliza los datos de un escaneo completo al formato del MER
 * 
 * @param {Object} rawScanData - Datos crudos del escaneo de docker.service.js
 * @returns {Object} Datos normalizados siguiendo la estructura del MER
 */
export function normalizeScanDataToMER(rawScanData) {
    const normalizedData = {
        simulation: normalizeSimulation(rawScanData),
        host: normalizeHost(rawScanData),
        ports: normalizePorts(rawScanData.ports || []),
        credentialTests: normalizeCredentialTests(rawScanData.credential_tests || [], rawScanData.ports || []),
        vulnerabilities: normalizeVulnerabilities(rawScanData),
        traceroute: normalizeTraceroute(rawScanData.traceroute || []),
        scripts: normalizeScripts(rawScanData.scripts || rawScanData.host_scripts || [])
    };

    return normalizedData;
}

/**
 * Normaliza los datos de la tabla Simulations
 * 
 * Campos del MER (SQL Real):
 * - id (INT AUTO_INCREMENT)
 * - user_id (INT NOT NULL)
 * - scan_type (ENUM: 'network_detect', 'discover', 'deep_scan')
 * - target_subnet (VARCHAR 50 NULL)
 * - target_ip (VARCHAR 45 NULL)
 * - status (ENUM: 'pending', 'running', 'completed', 'failed')
 * - start_time (TIMESTAMP NULL)
 * - end_time (TIMESTAMP NULL)
 * - scan_time_seconds (INT NULL)
 * - nmap_version (VARCHAR 50 NULL)
 * - nmap_command (TEXT NULL)
 * - error_message (TEXT NULL)
 * - json_response (LONGTEXT NULL)
 * - created_at (TIMESTAMP DEFAULT CURRENT_TIMESTAMP)
 */
function normalizeSimulation(rawData) {
    const now = new Date().toISOString();
    
    // Determinar scan_type basado en los datos
    let scanType = 'deep_scan'; // Por defecto
    if (rawData.subnet) {
        scanType = 'discover';
    } else if (rawData.scan_type) {
        scanType = rawData.scan_type;
    }
    
    // Parsear scan_time a segundos
    let scanTimeSeconds = null;
    if (rawData.scan_time) {
        const timeStr = String(rawData.scan_time);
        const match = timeStr.match(/(\d+)/);
        if (match) {
            scanTimeSeconds = parseInt(match[1]);
        }
    }
    
    return {
        id: generateSimulationId(),
        user_id: null, // Se asignara cuando haya autenticacion
        scan_type: scanType,
        target_subnet: rawData.subnet || null,
        target_ip: rawData.host || rawData.target || null,
        status: mapScanStatus(rawData.status),
        start_time: rawData.start_time || null,
        end_time: rawData.end_time || null,
        scan_time_seconds: scanTimeSeconds,
        nmap_version: rawData.nmap_version || null,
        nmap_command: rawData.nmap_command || null,
        error_message: rawData.error || rawData.error_message || null,
        json_response: rawData.raw_output || JSON.stringify(rawData),
        created_at: now
    };
}

/**
 * Normaliza los datos de la tabla Hosts
 * 
 * Campos del MER (SQL Real):
 * - id (INT AUTO_INCREMENT)
 * - simulation_id (INT NOT NULL)
 * - user_id (INT NOT NULL)
 * - ip_address (VARCHAR 45 NOT NULL)
 * - mac_address (VARCHAR 17 NULL)
 * - mac_vendor (VARCHAR 255 NULL)
 * - hostname (VARCHAR 255 NULL)
 * - os_detection (VARCHAR 255 NULL)
 * - device_type (VARCHAR 100 NULL)
 * - discovered_at (TIMESTAMP DEFAULT CURRENT_TIMESTAMP)
 * - last_scanned_at (TIMESTAMP NULL)
 */
function normalizeHost(rawData) {
    const networkInfo = rawData.network_info || {};
    const osDetection = rawData.os_detection || {};
    const now = new Date().toISOString();
    
    // Construir string de os_detection consolidado
    let osDetectionStr = null;
    if (osDetection.name) {
        osDetectionStr = osDetection.name;
        if (osDetection.accuracy) {
            osDetectionStr += ` (${osDetection.accuracy}% accuracy)`;
        }
        if (osDetection.os_family) {
            osDetectionStr += ` - ${osDetection.os_family}`;
        }
    }
    
    return {
        id: generateHostId(),
        simulation_id: null, // Se relacionara con la simulacion
        user_id: null, // Se asignara cuando haya autenticacion
        ip_address: rawData.host || networkInfo.ip || networkInfo.host_ip || null,
        mac_address: rawData.mac || networkInfo.mac || networkInfo.mac_address || null,
        mac_vendor: rawData.vendor || networkInfo.vendor || networkInfo.mac_vendor || null,
        hostname: rawData.hostname || networkInfo.hostname || null,
        os_detection: osDetectionStr,
        device_type: networkInfo.device_type || null,
        discovered_at: now,
        last_scanned_at: now
    };
}

/**
 * Normaliza los datos de la tabla Ports
 * 
 * Campos del MER (SQL Real):
 * - id (INT AUTO_INCREMENT)
 * - host_id (INT NOT NULL)
 * - port_number (INT NOT NULL)
 * - protocol (ENUM: 'tcp', 'udp' DEFAULT 'tcp')
 * - state (VARCHAR 50 NOT NULL)
 * - service (VARCHAR 100 NULL)
 * - product (VARCHAR 255 NULL)
 * - version (VARCHAR 100 NULL)
 * - cpe (VARCHAR 255 NULL)
 * - extra_info (TEXT NULL)
 * - discovered_at (TIMESTAMP DEFAULT CURRENT_TIMESTAMP)
 */
function normalizePorts(rawPorts) {
    if (!Array.isArray(rawPorts)) {
        return [];
    }

    return rawPorts.map((port, index) => ({
        id: generatePortId(index),
        host_id: null, // Se relacionara con el host
        port_number: parseInt(port.port || port.port_number || 0),
        protocol: (port.protocol || 'tcp').toLowerCase(),
        state: port.state || 'unknown',
        service: port.service || null,
        product: port.product || null,
        version: port.version || null,
        cpe: port.cpe || null,
        extra_info: port.extra_info || port.extrainfo || null,
        discovered_at: new Date().toISOString()
    }));
}

/**
 * Normaliza los datos de la tabla CredentialTests
 * 
 * Campos del MER (SQL Real):
 * - id (INT AUTO_INCREMENT)
 * - simulation_id (INT NOT NULL)
 * - host_id (INT NOT NULL)
 * - port_id (INT NOT NULL)
 * - user_id (INT NOT NULL)
 * - service (VARCHAR 100 NOT NULL)
 * - status (VARCHAR 100 NOT NULL)
 * - found_username (VARCHAR 255 NULL)
 * - found_password (VARCHAR 255 NULL)
 * - risk_score (TINYINT NULL)
 * - created_at (TIMESTAMP DEFAULT CURRENT_TIMESTAMP)
 */
function normalizeCredentialTests(rawCredentialTests, rawPorts) {
    if (!Array.isArray(rawCredentialTests)) {
        return [];
    }

    return rawCredentialTests.map((test, index) => {
        // Intentar encontrar el port_id correspondiente
        const portMatch = rawPorts.find(p => String(p.port) === String(test.port));
        const portId = portMatch ? generatePortId(rawPorts.indexOf(portMatch)) : null;

        // Extraer credenciales encontradas
        const credentials = test.credentials || [];
        const foundCred = credentials.find(c => c.success === true) || {};

        // Calcular risk_score basado en si se encontraron credenciales
        let riskScore = null;
        if (foundCred.username && foundCred.password) {
            riskScore = 10; // Maximo riesgo si se encontraron credenciales
        } else if (test.status === 'lockout_detected') {
            riskScore = 3; // Bajo riesgo, tiene proteccion
        } else if (test.status === 'rate_limited') {
            riskScore = 4; // Bajo-medio riesgo, tiene rate limiting
        } else {
            riskScore = 5; // Riesgo medio, no se pudo determinar
        }

        return {
            id: generateCredentialTestId(index),
            simulation_id: null, // Se relacionara con la simulacion
            host_id: null, // Se relacionara con el host
            port_id: portId,
            user_id: null, // Se asignara cuando haya autenticacion
            service: test.service || null,
            status: test.status || 'completed',
            found_username: foundCred.username || null,
            found_password: foundCred.password || null,
            risk_score: riskScore,
            created_at: new Date().toISOString()
        };
    });
}

/**
 * Normaliza vulnerabilidades de los scripts NSE
 * 
 * Campos del MER (SQL Real):
 * - id (INT AUTO_INCREMENT)
 * - simulation_id (INT NOT NULL)
 * - host_id (INT NOT NULL)
 * - port_id (INT NULL)
 * - script_id (VARCHAR 255 NOT NULL)
 * - severity (ENUM: 'critical', 'high', 'medium', 'low')
 * - output (LONGTEXT NULL)
 * - detected_at (TIMESTAMP DEFAULT CURRENT_TIMESTAMP)
 */
function normalizeVulnerabilities(rawData) {
    const vulnerabilities = [];
    
    // Vulnerabilidades explicitas del escaneo
    if (Array.isArray(rawData.vulnerabilities)) {
        rawData.vulnerabilities.forEach((vuln, index) => {
            vulnerabilities.push({
                id: generateVulnerabilityId(index),
                simulation_id: null, // Se relacionara con la simulacion
                host_id: null, // Se relacionara con el host
                port_id: null, // Se relacionara con el puerto si aplica
                script_id: vuln.script_id || 'unknown',
                severity: mapSeverityToMER(vuln.severity),
                output: vuln.output || vuln.description || null,
                detected_at: new Date().toISOString()
            });
        });
    }

    return vulnerabilities;
}

/**
 * Normaliza datos de traceroute
 */
function normalizeTraceroute(rawTraceroute) {
    if (!Array.isArray(rawTraceroute)) {
        return [];
    }
    
    return rawTraceroute.map((hop, index) => ({
        hop: index + 1,
        ip: hop.ip || hop.host || null,
        rtt: hop.rtt || hop.time || null,
        hostname: hop.hostname || null
    }));
}

/**
 * Normaliza scripts NSE
 */
function normalizeScripts(rawScripts) {
    if (!Array.isArray(rawScripts)) {
        return [];
    }
    
    return rawScripts.map(script => ({
        id: script.id || script.script_id || null,
        output: script.output || script.result || null,
        elements: script.elements || []
    }));
}

/**
 * Mapea el estado del escaneo al formato del MER
 * MER ENUM: 'pending', 'running', 'completed', 'failed'
 */
function mapScanStatus(rawStatus) {
    const statusMap = {
        'up': 'completed',
        'down': 'failed',
        'running': 'running',
        'in_progress': 'running',
        'pending': 'pending',
        'completed': 'completed',
        'failed': 'failed'
    };
    
    return statusMap[rawStatus] || 'completed';
}

/**
 * Mapea la severidad al formato del MER
 * MER ENUM: 'critical', 'high', 'medium', 'low'
 */
function mapSeverityToMER(rawSeverity) {
    if (!rawSeverity) return 'medium';
    
    const sev = String(rawSeverity).toLowerCase();
    const validSeverities = ['critical', 'high', 'medium', 'low'];
    
    if (validSeverities.includes(sev)) {
        return sev;
    }
    
    // Mapeo de variaciones
    if (sev.includes('crit')) return 'critical';
    if (sev.includes('high') || sev.includes('severe')) return 'high';
    if (sev.includes('low') || sev.includes('minor')) return 'low';
    
    return 'medium';
}

/**
 * Generadores de IDs simulados (cuando se integre BD, seran autoincrement)
 */
function generateSimulationId() {
    return `sim_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

function generateHostId() {
    return `host_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

function generatePortId(index) {
    return `port_${Date.now()}_${index}_${Math.random().toString(36).substr(2, 5)}`;
}

function generateCredentialTestId(index) {
    return `cred_${Date.now()}_${index}_${Math.random().toString(36).substr(2, 5)}`;
}

function generateVulnerabilityId(index) {
    return `vuln_${Date.now()}_${index}_${Math.random().toString(36).substr(2, 5)}`;
}

/**
 * Prepara los datos normalizados para el analisis con IA
 * 
 * Transforma la estructura del MER en el formato esperado por aiPromptBuilder.js
 */
export function prepareDataForAIAnalysis(normalizedData) {
    const { simulation, host, ports, credentialTests, vulnerabilities, traceroute, scripts } = normalizedData;

    // Parsear os_detection string de vuelta a componentes
    let osName = null;
    let osAccuracy = null;
    let osFamily = null;
    
    if (host.os_detection) {
        const accuracyMatch = host.os_detection.match(/\((\d+)% accuracy\)/);
        const familyMatch = host.os_detection.match(/ - (.+)$/);
        const nameMatch = host.os_detection.split(' (')[0];
        
        osName = nameMatch || host.os_detection;
        if (accuracyMatch) osAccuracy = parseInt(accuracyMatch[1]);
        if (familyMatch) osFamily = familyMatch[1];
    }

    return {
        // Informacion de la simulacion
        simulation_id: simulation.id,
        scan_type: simulation.scan_type,
        target: simulation.target_ip || simulation.target_subnet,
        scan_time: simulation.scan_time_seconds ? `${simulation.scan_time_seconds}s` : null,
        nmap_version: simulation.nmap_version,
        nmap_command: simulation.nmap_command,

        // Informacion del host
        host: host.ip_address,
        hostname: host.hostname,
        status: 'up',  // Si hay datos, el host esta up

        // Informacion de red
        network_info: {
            ip: host.ip_address,
            hostname: host.hostname,
            mac_address: host.mac_address,
            mac_vendor: host.mac_vendor,
            device_type: host.device_type,
            os_detection: host.os_detection,
            open_ports_count: ports.filter(p => p.state === 'open').length,
            services_detected: [...new Set(ports.filter(p => p.service).map(p => p.service))],
            traceroute_hops: traceroute.length
        },

        // Deteccion de SO (para compatibilidad con prompt)
        os_detection: osName ? {
            name: osName,
            accuracy: osAccuracy,
            os_family: osFamily
        } : null,

        // Puertos
        ports: ports.map(p => ({
            port: p.port_number,
            protocol: p.protocol,
            state: p.state,
            service: p.service,
            product: p.product,
            version: p.version,
            extra_info: p.extra_info,
            cpe: p.cpe
        })),

        // Pruebas de credenciales
        credential_tests: credentialTests.map(ct => ({
            service: ct.service,
            port: ports.find(p => p.id === ct.port_id)?.port_number || null,
            status: ct.status,
            credentials_found: !!(ct.found_username && ct.found_password),
            username: ct.found_username,
            password: ct.found_password,
            risk_score: ct.risk_score
        })),

        // Vulnerabilidades
        vulnerabilities: vulnerabilities.map(v => ({
            script_id: v.script_id,
            severity: v.severity,
            output: v.output
        })),

        // Traceroute
        traceroute: traceroute,

        // Scripts NSE
        scripts: scripts
    };
}

/**
 * Prepara la respuesta de IA para almacenamiento
 * 
 * NOTA: NO existe tabla AIAnalysis en el MER real.
 * El analisis de IA puede guardarse en Simulations.json_response
 * o en una tabla Reports como archivo JSON/PDF generado.
 * 
 * Esta funcion prepara el analisis para ser almacenado como JSON
 * en el campo json_response de Simulations.
 */
export function prepareAIAnalysisForStorage(aiResponse, simulationId) {
    return {
        ai_analysis: {
            simulation_id: simulationId,
            executive_summary: aiResponse.executive_summary || null,
            overall_risk_score: aiResponse.overall_risk_score || 0,
            risk_level: aiResponse.risk_level || 'UNKNOWN',
            analysis_confidence: aiResponse.analysis_confidence || 0.0,
            vulnerabilities: aiResponse.vulnerabilities || [],
            network_exposure: aiResponse.network_exposure || {},
            compliance_notes: aiResponse.compliance_notes || {},
            immediate_actions: aiResponse.immediate_actions || [],
            generated_at: new Date().toISOString()
        },
        analysis_metadata: {
            model: 'gpt-4o-mini',
            timestamp: new Date().toISOString(),
            version: '1.0'
        }
    };
}

// Valida que los datos normalizados tengan la estructura correcta del MER

export function validateNormalizedData(normalizedData) {
    const errors = [];

    // Validar Simulation (campos requeridos segun MER)
    if (!normalizedData.simulation) {
        errors.push('Missing simulation data');
    } else {
        // scan_type es requerido en el MER
        if (!normalizedData.simulation.scan_type) {
            errors.push('Simulation.scan_type is required');
        }
        
        // Debe tener target_ip o target_subnet
        if (!normalizedData.simulation.target_ip && !normalizedData.simulation.target_subnet) {
            errors.push('Simulation must have target_ip or target_subnet');
        }
        
        // status es requerido
        if (!normalizedData.simulation.status) {
            errors.push('Simulation.status is required');
        }
        
        // Validar ENUM de status
        const validStatuses = ['pending', 'running', 'completed', 'failed'];
        if (normalizedData.simulation.status && !validStatuses.includes(normalizedData.simulation.status)) {
            errors.push(`Simulation.status must be one of: ${validStatuses.join(', ')}`);
        }
        
        // Validar ENUM de scan_type
        const validScanTypes = ['network_detect', 'discover', 'deep_scan'];
        if (normalizedData.simulation.scan_type && !validScanTypes.includes(normalizedData.simulation.scan_type)) {
            errors.push(`Simulation.scan_type must be one of: ${validScanTypes.join(', ')}`);
        }
    }

    // Validar Host (campos requeridos segun MER)
    if (!normalizedData.host) {
        errors.push('Missing host data');
    } else {
        if (!normalizedData.host.ip_address) {
            errors.push('Host.ip_address is required');
        }
    }

    // Validar Ports
    if (!Array.isArray(normalizedData.ports)) {
        errors.push('Ports must be an array');
    } else {
        // Validar estructura de cada puerto
        normalizedData.ports.forEach((port, index) => {
            if (!port.port_number || typeof port.port_number !== 'number') {
                errors.push(`Port[${index}].port_number must be a number`);
            }
            if (!port.protocol || !['tcp', 'udp'].includes(port.protocol)) {
                errors.push(`Port[${index}].protocol must be 'tcp' or 'udp'`);
            }
            if (!port.state) {
                errors.push(`Port[${index}].state is required`);
            }
        });
    }

    // Validar CredentialTests
    if (!Array.isArray(normalizedData.credentialTests)) {
        errors.push('CredentialTests must be an array');
    }
    
    // Validar Vulnerabilities
    if (!Array.isArray(normalizedData.vulnerabilities)) {
        errors.push('Vulnerabilities must be an array');
    } else {
        normalizedData.vulnerabilities.forEach((vuln, index) => {
            if (!vuln.script_id) {
                errors.push(`Vulnerability[${index}].script_id is required`);
            }
            const validSeverities = ['critical', 'high', 'medium', 'low'];
            if (vuln.severity && !validSeverities.includes(vuln.severity)) {
                errors.push(`Vulnerability[${index}].severity must be one of: ${validSeverities.join(', ')}`);
            }
        });
    }

    return {
        valid: errors.length === 0,
        errors
    };
}
