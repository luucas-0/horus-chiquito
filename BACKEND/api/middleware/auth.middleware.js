import { getSession, parseBearerToken } from "../services/session.service.js";

export function requireAuth(req, res, next) {
    const token = parseBearerToken(req.headers.authorization || "");

    if (!token) {
        return res.status(401).json({
            success: false,
            error: "Authentication required"
        });
    }

    const session = getSession(token);
    if (!session) {
        return res.status(401).json({
            success: false,
            error: "Invalid or expired session"
        });
    }

    req.auth = session;
    req.authToken = token;
    return next();
}

export function requireAdmin(req, res, next) {
    if (!req.auth?.isAdmin) {
        return res.status(403).json({
            success: false,
            error: "Admin privileges required"
        });
    }

    return next();
}
