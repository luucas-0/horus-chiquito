import {
    authenticateUserCredentials,
    ensureAuthReady,
    getPublicUserById,
    registerStandardUser
} from "../services/user.service.js";
import { createSession, revokeSession } from "../services/session.service.js";

function normalizeError(error) {
    return {
        status: error?.status || 500,
        code: error?.code || "INTERNAL_ERROR",
        message: error?.message || "Unexpected error"
    };
}

function mapUserForClient(user) {
    return {
        id: user.id,
        email: user.email || user.username,
        username: user.username,
        full_name: user.full_name || null,
        is_active: Boolean(user.is_active),
        is_admin: Boolean(user.is_admin),
        roles: Array.isArray(user.roles) ? user.roles : [],
        created_at: user.created_at || null,
        last_login: user.last_login || null
    };
}

export async function login(req, res) {
    const identity = String(req.body?.username || req.body?.email || req.body?.user || "").trim();
    const password = String(req.body?.password || "");

    if (!identity || !password) {
        return res.status(400).json({
            success: false,
            error: "email/username and password are required"
        });
    }

    try {
        await ensureAuthReady();
        const user = await authenticateUserCredentials({ username: identity, password });

        if (!user) {
            return res.status(401).json({
                success: false,
                error: "Invalid credentials"
            });
        }

        const session = createSession(user);

        return res.status(200).json({
            success: true,
            token: session.token,
            expires_at: new Date(session.expiresAt).toISOString(),
            user: mapUserForClient(user)
        });
    } catch (error) {
        const normalized = normalizeError(error);
        return res.status(normalized.status).json({
            success: false,
            error: normalized.message,
            code: normalized.code
        });
    }
}

export async function register(req, res) {
    const email = String(req.body?.email || "").trim();
    const username = String(req.body?.username || req.body?.user || "").trim();
    const fullName = String(req.body?.full_name || req.body?.fullName || req.body?.nombre_completo || "").trim();
    const password = String(req.body?.password || "");

    if (!email || !username || !fullName || !password) {
        return res.status(400).json({
            success: false,
            error: "email, username, full_name and password are required"
        });
    }

    try {
        await ensureAuthReady();
        const user = await registerStandardUser({ email, username, fullName, password });
        const session = createSession(user);

        return res.status(201).json({
            success: true,
            token: session.token,
            expires_at: new Date(session.expiresAt).toISOString(),
            user: mapUserForClient(user)
        });
    } catch (error) {
        const normalized = normalizeError(error);
        return res.status(normalized.status).json({
            success: false,
            error: normalized.message,
            code: normalized.code
        });
    }
}

export async function me(req, res) {
    try {
        await ensureAuthReady();

        const user = await getPublicUserById(req.auth?.userId);
        if (!user) {
            return res.status(401).json({
                success: false,
                error: "Session user no longer exists"
            });
        }

        return res.status(200).json({
            success: true,
            user: mapUserForClient(user)
        });
    } catch (error) {
        const normalized = normalizeError(error);
        return res.status(normalized.status).json({
            success: false,
            error: normalized.message,
            code: normalized.code
        });
    }
}

export async function logout(req, res) {
    revokeSession(req.authToken);

    return res.status(200).json({
        success: true,
        message: "Session closed"
    });
}
