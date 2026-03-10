import {
    createUserByAdmin,
    deleteUserByAdmin,
    ensureAuthReady,
    listUsersForAdmin,
    updateUserByAdmin
} from "../services/user.service.js";
import { revokeAllUserSessions } from "../services/session.service.js";

function normalizeError(error) {
    return {
        status: error?.status || 500,
        code: error?.code || "INTERNAL_ERROR",
        message: error?.message || "Unexpected error"
    };
}

function parsePositiveInt(value) {
    const parsed = Number.parseInt(String(value ?? ""), 10);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
}

export async function listUsers(req, res) {
    try {
        await ensureAuthReady();
        const items = await listUsersForAdmin({ includeInactive: true });

        return res.status(200).json({
            success: true,
            count: items.length,
            items
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

export async function createUser(req, res) {
    const actorUserId = req.auth?.userId;

    try {
        await ensureAuthReady();

        const created = await createUserByAdmin(
            {
                email: req.body?.email,
                username: req.body?.username,
                fullName: req.body?.full_name,
                password: req.body?.password,
                isActive: req.body?.is_active,
                isAdmin: req.body?.is_admin
            },
            actorUserId
        );

        return res.status(201).json({
            success: true,
            user: created
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

export async function updateUser(req, res) {
    const actorUserId = req.auth?.userId;
    const targetUserId = parsePositiveInt(req.params.userId);

    if (!targetUserId) {
        return res.status(400).json({
            success: false,
            error: "userId must be a positive integer"
        });
    }

    try {
        await ensureAuthReady();

        const updated = await updateUserByAdmin(
            targetUserId,
            {
                email: req.body?.email,
                username: req.body?.username,
                full_name: req.body?.full_name,
                password: req.body?.password,
                is_active: req.body?.is_active,
                is_admin: req.body?.is_admin
            },
            actorUserId
        );

        if (updated.id === actorUserId) {
            revokeAllUserSessions(actorUserId);
        }

        return res.status(200).json({
            success: true,
            user: updated,
            note: updated.id === actorUserId
                ? "Current admin sessions were refreshed. Please log in again if needed."
                : undefined
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

export async function deleteUser(req, res) {
    const actorUserId = req.auth?.userId;
    const targetUserId = parsePositiveInt(req.params.userId);

    if (!targetUserId) {
        return res.status(400).json({
            success: false,
            error: "userId must be a positive integer"
        });
    }

    try {
        await ensureAuthReady();
        const deleted = await deleteUserByAdmin(targetUserId, actorUserId);

        revokeAllUserSessions(targetUserId);

        return res.status(200).json({
            success: true,
            deleted
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
