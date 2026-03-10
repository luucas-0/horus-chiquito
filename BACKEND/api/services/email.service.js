import { getMailConfig, isMailConfigured } from "../config/mail.config.js";

let nodemailerModulePromise = null;

async function getNodemailerModule() {
    if (!nodemailerModulePromise) {
        nodemailerModulePromise = (async () => {
            try {
                const module = await import("nodemailer");
                return module.default;
            } catch {
                throw new Error("nodemailer package is missing. Run npm install in /BACKEND/api.");
            }
        })();
    }

    return nodemailerModulePromise;
}

function buildTransportConfig(config) {
    const transport = {
        host: config.host,
        port: config.port,
        secure: config.secure,
        tls: {
            rejectUnauthorized: !config.allowInsecureTLS
        }
    };

    if (config.user && config.password) {
        transport.auth = {
            user: config.user,
            pass: config.password
        };
    }

    return transport;
}

export async function sendEmailMessage({ to, subject, text, html, attachments = [] } = {}) {
    if (!to) {
        throw new Error("Email recipient is required");
    }

    if (!subject) {
        throw new Error("Email subject is required");
    }

    if (!isMailConfigured()) {
        throw new Error("SMTP is not configured. Set SMTP_HOST and SMTP_FROM in BACKEND/api/.env");
    }

    const config = getMailConfig();
    const nodemailer = await getNodemailerModule();
    const transporter = nodemailer.createTransport(buildTransportConfig(config));

    try {
        return await transporter.sendMail({
            from: config.from,
            to,
            subject,
            text: text || undefined,
            html: html || undefined,
            attachments: Array.isArray(attachments) ? attachments : []
        });
    } catch (error) {
        throw new Error(`SMTP send failed: ${error.message}`);
    }
}
