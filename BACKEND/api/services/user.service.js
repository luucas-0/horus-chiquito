import crypto from "crypto";
import { execute, isDbEnabled, testDbConnection } from "../config/db.js";

const LEGACY_USERNAME_REGEX = /^[a-zA-Z0-9_.-]{3,40}$/;
const ACCOUNT_USERNAME_REGEX = /^[a-zA-Z0-9_.-]{3,40}$/;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const DEFAULT_ADMIN_USERNAME = String(process.env.DEFAULT_ADMIN_USERNAME || "admin").trim().toLowerCase();
const DEFAULT_ADMIN_PASSWORD = String(process.env.DEFAULT_ADMIN_PASSWORD || "horus2026");
const PASSWORD_HASH_ITERATIONS = Number.parseInt(process.env.PASSWORD_HASH_ITERATIONS || "120000", 10) || 120000;
const PASSWORD_HASH_KEY_LENGTH = 64;
const PASSWORD_HASH_DIGEST = "sha512";
const tableExistsCache = new Map();
const columnExistsCache = new Map();
const indexExistsCache = new Map();

function makeError(message, status = 400, code = "BAD_REQUEST") {
    const error = new Error(message);
    error.status = status;
    error.code = code;
    return error;
}

function normalizeIdentifier(value) {
    return String(value || "").trim().toLowerCase();
}

function normalizeFullName(value) {
    return String(value || "").trim().replace(/\s+/g, " ");
}

function normalizeUsernameCandidate(value) {
    return normalizeIdentifier(value).replace(/[^a-z0-9_.-]/g, "");
}

function parseBoolean(value, fallback = null) {
    if (typeof value === "boolean") {
        return value;
    }

    if (value == null) {
        return fallback;
    }

    const normalized = String(value).trim().toLowerCase();
    if (["1", "true", "yes", "si", "on"].includes(normalized)) {
        return true;
    }

    if (["0", "false", "no", "off"].includes(normalized)) {
        return false;
    }

    return fallback;
}

async function hasTable(tableName) {
    if (!isDbEnabled()) {
        return false;
    }

    if (tableExistsCache.has(tableName)) {
        return tableExistsCache.get(tableName);
    }

    const [rows] = await execute(
        `SELECT 1 AS exists_flag
         FROM information_schema.tables
         WHERE table_schema = DATABASE()
           AND table_name = ?
         LIMIT 1`,
        [tableName]
    );

    const exists = Array.isArray(rows) && rows.length > 0;
    tableExistsCache.set(tableName, exists);
    return exists;
}

async function hasColumn(tableName, columnName) {
    const key = `${tableName}.${columnName}`;
    if (columnExistsCache.has(key)) {
        return columnExistsCache.get(key);
    }

    const [rows] = await execute(
        `SELECT 1 AS exists_flag
         FROM information_schema.columns
         WHERE table_schema = DATABASE()
           AND table_name = ?
           AND column_name = ?
         LIMIT 1`,
        [tableName, columnName]
    );

    const exists = Array.isArray(rows) && rows.length > 0;
    columnExistsCache.set(key, exists);
    return exists;
}

async function hasIndex(tableName, indexName) {
    const key = `${tableName}.${indexName}`;
    if (indexExistsCache.has(key)) {
        return indexExistsCache.get(key);
    }

    const [rows] = await execute(
        `SELECT 1 AS exists_flag
         FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = ?
           AND index_name = ?
         LIMIT 1`,
        [tableName, indexName]
    );

    const exists = Array.isArray(rows) && rows.length > 0;
    indexExistsCache.set(key, exists);
    return exists;
}

async function hasRoleTables() {
    return (await hasTable("Roles")) && (await hasTable("UserRoles"));
}

async function ensureUsersSchema() {
    if (!(await hasTable("Users"))) {
        return;
    }

    if (!(await hasColumn("Users", "username"))) {
        await execute(`ALTER TABLE Users ADD COLUMN username VARCHAR(255) NULL AFTER email`);
        columnExistsCache.set("Users.username", true);
    }

    if (!(await hasColumn("Users", "full_name"))) {
        await execute(`ALTER TABLE Users ADD COLUMN full_name VARCHAR(255) NULL AFTER username`);
        columnExistsCache.set("Users.full_name", true);
    }

    await execute(
        `UPDATE Users
         SET username = LOWER(TRIM(email))
         WHERE username IS NULL OR TRIM(username) = ''`
    );

    if (!(await hasIndex("Users", "users_username_unique"))) {
        await execute(`ALTER TABLE Users ADD UNIQUE users_username_unique (username)`);
        indexExistsCache.set("Users.users_username_unique", true);
    }
}

async function writeAudit(userId, action, resourceId, details = {}) {
    if (!(await hasTable("AuditLog"))) {
        return;
    }

    const safeUserId = Number.parseInt(String(userId ?? ""), 10);
    if (!Number.isFinite(safeUserId) || safeUserId <= 0) {
        return;
    }

    await execute(
        `INSERT INTO AuditLog (user_id, action, resource_type, resource_id, details)
         VALUES (?, ?, 'Users', ?, ?)`,
        [safeUserId, action, resourceId || null, JSON.stringify(details || {})]
    ).catch(() => {
        // no-op
    });
}

function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString("hex");
    const hash = crypto
        .pbkdf2Sync(String(password), salt, PASSWORD_HASH_ITERATIONS, PASSWORD_HASH_KEY_LENGTH, PASSWORD_HASH_DIGEST)
        .toString("hex");

    return `pbkdf2$${PASSWORD_HASH_DIGEST}$${PASSWORD_HASH_ITERATIONS}$${salt}$${hash}`;
}

function verifyPassword(plainPassword, storedHash) {
    const password = String(plainPassword || "");
    const serialized = String(storedHash || "");

    if (!serialized) {
        return false;
    }

    if (!serialized.startsWith("pbkdf2$")) {
        return password === serialized;
    }

    const parts = serialized.split("$");
    if (parts.length !== 5) {
        return false;
    }

    const [, digest, iterationsRaw, salt, expectedHash] = parts;
    const iterations = Number.parseInt(iterationsRaw, 10);

    if (!digest || !salt || !expectedHash || !Number.isFinite(iterations) || iterations <= 0) {
        return false;
    }

    const computed = crypto
        .pbkdf2Sync(password, salt, iterations, PASSWORD_HASH_KEY_LENGTH, digest)
        .toString("hex");

    try {
        return crypto.timingSafeEqual(Buffer.from(computed, "hex"), Buffer.from(expectedHash, "hex"));
    } catch {
        return false;
    }
}

function validateUsername(username) {
    if (!username) {
        throw makeError("Username or email is required", 400, "USERNAME_REQUIRED");
    }

    const candidate = normalizeIdentifier(username);
    if (!EMAIL_REGEX.test(candidate) && !LEGACY_USERNAME_REGEX.test(candidate)) {
        throw makeError(
            "Username/email format is invalid",
            400,
            "USERNAME_INVALID"
        );
    }
}

function validateAccountUsername(username) {
    if (!username) {
        throw makeError("Username is required", 400, "USERNAME_REQUIRED");
    }

    const candidate = normalizeIdentifier(username);
    if (!ACCOUNT_USERNAME_REGEX.test(candidate)) {
        throw makeError(
            "Username must contain 3-40 characters (letters, numbers, ., _, -)",
            400,
            "USERNAME_INVALID"
        );
    }

    return candidate;
}

function validateEmail(email) {
    if (!email) {
        throw makeError("Email is required", 400, "EMAIL_REQUIRED");
    }

    const candidate = normalizeIdentifier(email);
    if (!EMAIL_REGEX.test(candidate)) {
        throw makeError("Email format is invalid", 400, "EMAIL_INVALID");
    }

    return candidate;
}

function validateFullName(fullName) {
    const candidate = normalizeFullName(fullName);
    if (!candidate) {
        throw makeError("Full name is required", 400, "FULL_NAME_REQUIRED");
    }

    if (candidate.length < 3) {
        throw makeError("Full name must be at least 3 characters", 400, "FULL_NAME_TOO_SHORT");
    }

    return candidate;
}

function validatePassword(password) {
    if (!password) {
        throw makeError("Password is required", 400, "PASSWORD_REQUIRED");
    }

    if (String(password).length < 6) {
        throw makeError("Password must be at least 6 characters", 400, "PASSWORD_TOO_SHORT");
    }
}

function deriveUsernameFromEmail(email) {
    const localPart = String(email || "").split("@")[0] || "";
    return normalizeUsernameCandidate(localPart);
}

async function buildAvailableUsername(preferredUsername, fallbackEmail, excludeUserId = null) {
    let base = normalizeUsernameCandidate(preferredUsername);
    if (!base) {
        base = deriveUsernameFromEmail(fallbackEmail);
    }

    if (!base || base.length < 3) {
        base = `user${Date.now().toString().slice(-8)}`;
    }

    base = base.slice(0, 40);
    if (base.length < 3) {
        base = "user000";
    }

    let candidate = base;
    let attempt = 1;

    while (true) {
        const byUsername = await getUserRowByAccountUsername(candidate);
        const byEmail = await getUserRowByEmail(candidate);

        const usernameConflict = byUsername && byUsername.id !== excludeUserId;
        const emailConflict = byEmail && byEmail.id !== excludeUserId;

        if (!usernameConflict && !emailConflict) {
            return candidate;
        }

        const suffix = `_${attempt}`;
        const maxBase = Math.max(3, 40 - suffix.length);
        candidate = `${base.slice(0, maxBase)}${suffix}`;
        attempt += 1;
    }
}

async function ensureRole(roleName, description) {
    if (!(await hasRoleTables())) {
        return null;
    }

    await execute(
        `INSERT INTO Roles (name, description)
         VALUES (?, ?)
         ON DUPLICATE KEY UPDATE description = COALESCE(VALUES(description), description)`,
        [roleName, description || null]
    );

    const [[row]] = await execute(`SELECT id FROM Roles WHERE name = ? LIMIT 1`, [roleName]);
    return row?.id || null;
}

async function setRoleForUser(userId, roleName) {
    if (!(await hasRoleTables())) {
        return;
    }

    const roleId = await ensureRole(
        roleName,
        roleName === "admin" ? "Administrador del sistema" : "Usuario estandar"
    );

    if (!roleId) {
        return;
    }

    await execute(`DELETE FROM UserRoles WHERE user_id = ?`, [userId]);
    await execute(`INSERT INTO UserRoles (user_id, role_id) VALUES (?, ?)`, [userId, roleId]);
}

async function getRolesForUser(userId, identity) {
    if (await hasRoleTables()) {
        const [rows] = await execute(
            `SELECT r.name
             FROM UserRoles ur
             INNER JOIN Roles r ON r.id = ur.role_id
             WHERE ur.user_id = ?`,
            [userId]
        );

        const dbRoles = rows
            .map((row) => String(row?.name || "").trim().toLowerCase())
            .filter(Boolean);

        if (dbRoles.length > 0) {
            return dbRoles;
        }
    }

    return identity === DEFAULT_ADMIN_USERNAME ? ["admin"] : ["user"];
}

function toPublicUser(row, roles) {
    const normalizedRoles = Array.isArray(roles) ? roles : [];
    const publicUsername = row.username || row.email;

    return {
        id: row.id,
        email: row.email,
        username: publicUsername,
        full_name: row.full_name || null,
        is_active: Boolean(row.is_active),
        created_at: row.created_at || null,
        last_login: row.last_login || null,
        roles: normalizedRoles,
        is_admin:
            normalizedRoles.includes("admin") ||
            publicUsername === DEFAULT_ADMIN_USERNAME ||
            row.email === DEFAULT_ADMIN_USERNAME
    };
}

async function getUserRowByIdentity(identity) {
    const normalizedIdentity = normalizeIdentifier(identity);

    const [[row]] = await execute(
        `SELECT id, email, username, full_name, password_hash, is_active, created_at, last_login
         FROM Users
         WHERE email = ? OR username = ?
         LIMIT 1`,
        [normalizedIdentity, normalizedIdentity]
    );

    return row || null;
}

async function getUserRowByEmail(email) {
    const normalizedEmail = normalizeIdentifier(email);

    const [[row]] = await execute(
        `SELECT id, email, username, full_name, password_hash, is_active, created_at, last_login
         FROM Users
         WHERE email = ?
         LIMIT 1`,
        [normalizedEmail]
    );

    return row || null;
}

async function getUserRowByAccountUsername(username) {
    const normalizedUsername = normalizeIdentifier(username);

    const [[row]] = await execute(
        `SELECT id, email, username, full_name, password_hash, is_active, created_at, last_login
         FROM Users
         WHERE username = ?
         LIMIT 1`,
        [normalizedUsername]
    );

    return row || null;
}

async function ensureIdentityAvailability({ email, username, excludeUserId = null }) {
    const normalizedEmail = normalizeIdentifier(email);
    const normalizedUsername = normalizeIdentifier(username);

    const checks = [
        {
            row: await getUserRowByEmail(normalizedEmail),
            message: "Email already exists",
            code: "EMAIL_TAKEN"
        },
        {
            row: await getUserRowByAccountUsername(normalizedUsername),
            message: "Username already exists",
            code: "USERNAME_TAKEN"
        },
        {
            row: await getUserRowByAccountUsername(normalizedEmail),
            message: "Email conflicts with an existing username",
            code: "EMAIL_CONFLICT"
        },
        {
            row: await getUserRowByEmail(normalizedUsername),
            message: "Username conflicts with an existing email",
            code: "USERNAME_CONFLICT"
        }
    ];

    for (const check of checks) {
        if (check.row && check.row.id !== excludeUserId) {
            throw makeError(check.message, 409, check.code);
        }
    }
}

async function getUserRowById(userId) {
    const numericUserId = Number.parseInt(String(userId ?? ""), 10);
    if (!Number.isFinite(numericUserId) || numericUserId <= 0) {
        return null;
    }

    const [[row]] = await execute(
        `SELECT id, email, username, full_name, password_hash, is_active, created_at, last_login
         FROM Users
         WHERE id = ?
         LIMIT 1`,
        [numericUserId]
    );

    return row || null;
}

async function getPublicUserByRow(row) {
    if (!row) {
        return null;
    }

    const identity = row.username || row.email;
    const roles = await getRolesForUser(row.id, identity);
    return toPublicUser(row, roles);
}

export async function ensureAuthReady() {
    if (!isDbEnabled()) {
        throw makeError("Database persistence is disabled", 503, "DB_DISABLED");
    }

    await testDbConnection().catch((error) => {
        throw makeError(`Database unavailable: ${error.message}`, 503, "DB_UNAVAILABLE");
    });

    if (!(await hasTable("Users"))) {
        throw makeError("Users table not found. Import schema.mysql.sql first.", 503, "USERS_TABLE_MISSING");
    }

    await ensureUsersSchema();

    await ensureRole("admin", "Administrador del sistema").catch(() => {
        // no-op
    });
    await ensureRole("user", "Usuario estandar").catch(() => {
        // no-op
    });

    await ensureDefaultAdminUser();
}

export async function ensureDefaultAdminUser() {
    const adminIdentity = normalizeIdentifier(DEFAULT_ADMIN_USERNAME);

    let adminRow = await getUserRowByIdentity(adminIdentity);

    if (!adminRow) {
        const [result] = await execute(
            `INSERT INTO Users (email, username, full_name, password_hash, is_active)
             VALUES (?, ?, ?, ?, 1)`,
            [adminIdentity, adminIdentity, "Administrador", hashPassword(DEFAULT_ADMIN_PASSWORD)]
        );

        adminRow = await getUserRowById(result.insertId);
    }

    if (adminRow) {
        const updates = [];
        const params = [];

        if (!adminRow.username) {
            updates.push("username = ?");
            params.push(adminIdentity);
        }

        if (!adminRow.full_name) {
            updates.push("full_name = ?");
            params.push("Administrador");
        }

        if (!adminRow.is_active) {
            updates.push("is_active = 1");
        }

        if (updates.length > 0) {
            params.push(adminRow.id);
            await execute(`UPDATE Users SET ${updates.join(", ")} WHERE id = ?`, params);
            adminRow = await getUserRowById(adminRow.id);
        }

        await setRoleForUser(adminRow.id, "admin").catch(() => {
            // no-op
        });
    }

    return getPublicUserByRow(adminRow);
}

export async function authenticateUserCredentials({ username, password }) {
    const normalizedUsername = normalizeIdentifier(username);
    const plainPassword = String(password || "");

    validateUsername(normalizedUsername);
    validatePassword(plainPassword);

    const row = await getUserRowByIdentity(normalizedUsername);
    if (!row || !row.is_active) {
        return null;
    }

    if (!verifyPassword(plainPassword, row.password_hash)) {
        return null;
    }

    await execute(`UPDATE Users SET last_login = NOW() WHERE id = ?`, [row.id]).catch(() => {
        // no-op
    });

    const updatedRow = await getUserRowById(row.id);
    return getPublicUserByRow(updatedRow || row);
}

export async function registerStandardUser({ email, username, fullName, password }) {
    const normalizedEmail = validateEmail(email);
    const normalizedUsername = validateAccountUsername(username);
    const normalizedFullName = validateFullName(fullName);
    const plainPassword = String(password || "");

    validatePassword(plainPassword);

    await ensureIdentityAvailability({
        email: normalizedEmail,
        username: normalizedUsername
    });

    const [result] = await execute(
        `INSERT INTO Users (email, username, full_name, password_hash, is_active)
         VALUES (?, ?, ?, ?, 1)`,
        [normalizedEmail, normalizedUsername, normalizedFullName, hashPassword(plainPassword)]
    );

    await setRoleForUser(result.insertId, "user").catch(() => {
        // no-op
    });

    const created = await getUserRowById(result.insertId);
    return getPublicUserByRow(created);
}

export async function getPublicUserById(userId) {
    const row = await getUserRowById(userId);
    if (!row) {
        return null;
    }

    return getPublicUserByRow(row);
}

export async function listUsersForAdmin({ includeInactive = true } = {}) {
    const includeInactiveFlag = parseBoolean(includeInactive, true);

    if (await hasRoleTables()) {
        const [rows] = await execute(
            `SELECT
                u.id,
                u.email,
                u.username,
                u.full_name,
                u.is_active,
                u.created_at,
                u.last_login,
                GROUP_CONCAT(r.name ORDER BY r.name SEPARATOR ',') AS role_names
             FROM Users u
             LEFT JOIN UserRoles ur ON ur.user_id = u.id
             LEFT JOIN Roles r ON r.id = ur.role_id
             WHERE u.email NOT LIKE 'system+%@horus.local'
               AND u.email NOT LIKE 'deleted_%'
               AND (? = 1 OR u.is_active = 1)
             GROUP BY u.id, u.email, u.username, u.full_name, u.is_active, u.created_at, u.last_login
             ORDER BY u.id ASC`,
            [includeInactiveFlag ? 1 : 0]
        );

        return rows.map((row) => {
            const roles = String(row.role_names || "")
                .split(",")
                .map((role) => role.trim().toLowerCase())
                .filter(Boolean);

            const normalizedRoles = roles.length > 0
                ? roles
                : (row.username || row.email) === DEFAULT_ADMIN_USERNAME
                    ? ["admin"]
                    : ["user"];

            return toPublicUser(row, normalizedRoles);
        });
    }

    const [rows] = await execute(
        `SELECT id, email, username, full_name, is_active, created_at, last_login
         FROM Users
         WHERE email NOT LIKE 'system+%@horus.local'
           AND email NOT LIKE 'deleted_%'
           AND (? = 1 OR is_active = 1)
         ORDER BY id ASC`,
        [includeInactiveFlag ? 1 : 0]
    );

    return rows.map((row) =>
        toPublicUser(row, (row.username || row.email) === DEFAULT_ADMIN_USERNAME ? ["admin"] : ["user"])
    );
}

export async function createUserByAdmin(
    { email, username, fullName, password, isActive = true, isAdmin = false },
    actorUserId
) {
    const normalizedEmail = validateEmail(email || username);
    const plainPassword = String(password || "");
    const activeFlag = parseBoolean(isActive, true);
    const adminFlag = parseBoolean(isAdmin, false);

    validatePassword(plainPassword);

    const normalizedUsername = username
        ? validateAccountUsername(username)
        : await buildAvailableUsername("", normalizedEmail);

    await ensureIdentityAvailability({
        email: normalizedEmail,
        username: normalizedUsername
    });

    const normalizedFullName = normalizeFullName(fullName);

    const [result] = await execute(
        `INSERT INTO Users (email, username, full_name, password_hash, is_active)
         VALUES (?, ?, ?, ?, ?)`,
        [
            normalizedEmail,
            normalizedUsername,
            // normalizedFullName || null,
            hashPassword(plainPassword),
            activeFlag ? 1 : 0
        ]
    );

    await setRoleForUser(result.insertId, adminFlag ? "admin" : "user").catch(() => {
        // no-op
    });

    await writeAudit(actorUserId, "user_created", result.insertId, {
        email: normalizedEmail,
        username: normalizedUsername,
        full_name: normalizedFullName || null,
        is_admin: adminFlag,
        is_active: activeFlag
    });

    const created = await getUserRowById(result.insertId);
    return getPublicUserByRow(created);
}

export async function updateUserByAdmin(userId, payload = {}, actorUserId) {
    const targetId = Number.parseInt(String(userId ?? ""), 10);
    if (!Number.isFinite(targetId) || targetId <= 0) {
        throw makeError("userId must be a positive integer", 400, "INVALID_USER_ID");
    }

    const target = await getUserRowById(targetId);
    if (!target) {
        throw makeError("User not found", 404, "USER_NOT_FOUND");
    }

    if (target.email.startsWith("system+")) {
        throw makeError("System users cannot be modified", 400, "SYSTEM_USER_IMMUTABLE");
    }

    const updates = [];
    const params = [];

    const currentUsername = target.username || target.email;

    const nextEmail = payload.email != null
        ? validateEmail(payload.email)
        : target.email;

    const nextUsername = payload.username != null
        ? validateAccountUsername(payload.username)
        : currentUsername;

    if (nextEmail !== target.email || nextUsername !== currentUsername) {
        await ensureIdentityAvailability({
            email: nextEmail,
            username: nextUsername,
            excludeUserId: target.id
        });
    }

    if (nextEmail !== target.email) {
        updates.push("email = ?");
        params.push(nextEmail);
    }

    if (nextUsername !== currentUsername) {
        updates.push("username = ?");
        params.push(nextUsername);
    }

    if (payload.full_name != null) {
        const nextFullName = normalizeFullName(payload.full_name);
        const currentFullName = target.full_name || "";

        if (nextFullName !== currentFullName) {
            if (!nextFullName) {
                updates.push("full_name = NULL");
            } else {
                updates.push("full_name = ?");
                params.push(nextFullName);
            }
        }
    }

    if (payload.password != null && String(payload.password).trim() !== "") {
        validatePassword(payload.password);
        updates.push("password_hash = ?");
        params.push(hashPassword(payload.password));
    }

    const nextActive = parseBoolean(payload.is_active, null);
    if (nextActive != null) {
        const numericActorId = Number.parseInt(String(actorUserId ?? ""), 10);
        if (!nextActive && Number.isFinite(numericActorId) && numericActorId === target.id) {
            throw makeError("You cannot deactivate your own account", 400, "SELF_DEACTIVATE_BLOCKED");
        }

        updates.push("is_active = ?");
        params.push(nextActive ? 1 : 0);
    }

    const targetIdentity = currentUsername || target.email;
    const nextAdmin = parseBoolean(payload.is_admin, null);
    if (nextAdmin === false && targetIdentity === DEFAULT_ADMIN_USERNAME) {
        throw makeError("Default admin role cannot be removed", 400, "DEFAULT_ADMIN_PROTECTED");
    }

    if (updates.length > 0) {
        params.push(target.id);
        await execute(`UPDATE Users SET ${updates.join(", ")} WHERE id = ?`, params);
    }

    if (nextAdmin != null) {
        await setRoleForUser(target.id, nextAdmin ? "admin" : "user").catch(() => {
            // no-op
        });
    }

    await writeAudit(actorUserId, "user_updated", target.id, {
        email_changed: nextEmail !== target.email,
        username_changed: nextUsername !== currentUsername,
        full_name_changed: payload.full_name != null,
        password_changed: payload.password != null && String(payload.password).trim() !== "",
        active_changed: nextActive != null,
        admin_changed: nextAdmin != null
    });

    const updated = await getUserRowById(target.id);
    return getPublicUserByRow(updated);
}

export async function deleteUserByAdmin(userId, actorUserId) {
    const targetId = Number.parseInt(String(userId ?? ""), 10);
    if (!Number.isFinite(targetId) || targetId <= 0) {
        throw makeError("userId must be a positive integer", 400, "INVALID_USER_ID");
    }

    const target = await getUserRowById(targetId);
    if (!target) {
        throw makeError("User not found", 404, "USER_NOT_FOUND");
    }

    if (target.email.startsWith("system+")) {
        throw makeError("System users cannot be deleted", 400, "SYSTEM_USER_IMMUTABLE");
    }

    const numericActorId = Number.parseInt(String(actorUserId ?? ""), 10);
    if (Number.isFinite(numericActorId) && numericActorId === target.id) {
        throw makeError("You cannot delete your own account", 400, "SELF_DELETE_BLOCKED");
    }

    const targetIdentity = target.username || target.email;
    if (targetIdentity === DEFAULT_ADMIN_USERNAME || target.email === DEFAULT_ADMIN_USERNAME) {
        throw makeError("Default admin account cannot be deleted", 400, "DEFAULT_ADMIN_PROTECTED");
    }

    const stamp = Date.now();
    const tombstoneEmail = `deleted_${target.id}_${stamp}@deleted.local`;
    const tombstoneUsername = `deleted_${target.id}_${stamp}`;

    await execute(
        `UPDATE Users
         SET email = ?, username = ?, full_name = NULL, is_active = 0, password_hash = 'deleted-account'
         WHERE id = ?`,
        [tombstoneEmail, tombstoneUsername, target.id]
    );

    if (await hasRoleTables()) {
        await execute(`DELETE FROM UserRoles WHERE user_id = ?`, [target.id]);
    }

    await writeAudit(actorUserId, "user_deleted", target.id, {
        previous_email: target.email,
        previous_username: target.username || target.email,
        tombstone_email: tombstoneEmail,
        tombstone_username: tombstoneUsername
    });

    return {
        id: target.id,
        deleted: true
    };
}
