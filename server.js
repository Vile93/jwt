require("dotenv").config();
const crypto = require("node:crypto");
const path = require("node:path");
const bcrypt = require("bcryptjs");
const cookie = require("cookie");
const express = require("express");
const jwt = require("jsonwebtoken");
const Db = require("./db");

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_FILE =
    process.env.DATABASE_FILE || path.join(__dirname, "auth.sqlite");
const ACCESS_TOKEN_TTL = "15m";
const REFRESH_TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const ACCESS_COOKIE = "access_token";
const REFRESH_COOKIE = "refresh_token";
const COOKIE_OPTIONS = {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
};

if (!JWT_SECRET) {
    throw new Error("JWT_SECRET environment variable is required");
}

const db = new Db(DATABASE_FILE);

const app = express();
app.use(express.json({ limit: "10kb" }));

function publicUser(user) {
    return {
        id: user.id,
        name: user.name,
        roles: JSON.parse(user.roles_json),
    };
}

function hashRefreshToken(token) {
    return crypto.createHash("sha256").update(token).digest("hex");
}

function createAccessToken(user) {
    return jwt.sign(
        {
            sub: String(user.id),
            name: user.name,
            roles: JSON.parse(user.roles_json),
            type: "access",
        },
        JWT_SECRET,
        { algorithm: "HS256", expiresIn: ACCESS_TOKEN_TTL },
    );
}

function issueTokenPair(user, previousTokenHash = null) {
    const refreshToken = crypto.randomBytes(32).toString("base64url");
    const refreshTokenExpiresAt = Date.now() + REFRESH_TOKEN_TTL_MS;

    if (previousTokenHash) {
        db.revokeRefreshToken(previousTokenHash);
    }
    db.createRefreshToken(
        user.id,
        hashRefreshToken(refreshToken),
        refreshTokenExpiresAt,
    );

    return {
        accessToken: createAccessToken(user),
        refreshToken,
        tokenType: "Bearer",
        expiresIn: 15 * 60,
    };
}

function setAuthCookies(res, tokens) {
    res.cookie(ACCESS_COOKIE, tokens.accessToken, {
        ...COOKIE_OPTIONS,
        maxAge: 15 * 60 * 1000,
        path: "/",
    });
    res.cookie(REFRESH_COOKIE, tokens.refreshToken, {
        ...COOKIE_OPTIONS,
        maxAge: REFRESH_TOKEN_TTL_MS,
        path: "/auth",
    });
}

function clearAuthCookies(res) {
    res.clearCookie(ACCESS_COOKIE, { ...COOKIE_OPTIONS, path: "/" });
    res.clearCookie(REFRESH_COOKIE, { ...COOKIE_OPTIONS, path: "/auth" });
}

function requestCookies(req) {
    return cookie.parse(req.headers.cookie || "");
}

function getUserById(id) {
    return db.findUserById(id);
}

function requireAccessToken(req, res, next) {
    const cookies = requestCookies(req);
    const authorization = req.get("authorization");
    const token =
        cookies[ACCESS_COOKIE] ||
        (authorization && authorization.startsWith("Bearer ")
            ? authorization.slice("Bearer ".length).trim()
            : null);

    if (!token) {
        return res.status(401).json({ error: "ACCESS_TOKEN_REQUIRED" });
    }

    try {
        const payload = jwt.verify(token, JWT_SECRET, {
            algorithms: ["HS256"],
        });
        if (
            !payload ||
            payload.type !== "access" ||
            typeof payload.sub !== "string"
        ) {
            return res.status(401).json({ error: "ACCESS_TOKEN_INVALID" });
        }

        const user = getUserById(Number(payload.sub));
        if (!user) {
            return res.status(401).json({ error: "ACCESS_TOKEN_INVALID" });
        }

        req.user = publicUser(user);
        next();
    } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            return res.status(401).json({ error: "TOKEN_EXPIRED" });
        }
        return res.status(401).json({ error: "ACCESS_TOKEN_INVALID" });
    }
}

function requireString(value, field) {
    if (typeof value !== "string" || value.trim() === "") {
        const error = new Error(`${field} must be a non-empty string`);
        error.status = 400;
        error.code = "VALIDATION_ERROR";
        throw error;
    }
    return value.trim();
}

app.get("/health", (req, res) => {
    res.status(200).json({ status: "ok 123" });
});
app.post("/auth/register", (req, res, next) => {
    try {
        const name = requireString(req.body.name, "name");
        const password = requireString(req.body.password, "password");
        if (password.length < 8) {
            return res.status(400).json({
                error: "VALIDATION_ERROR",
                message: "password must contain at least 8 characters",
            });
        }

        const passwordHash = bcrypt.hashSync(password, 12);
        const user = db.createUser(name, passwordHash);
        return res.status(201).json({ user: publicUser(user) });
    } catch (error) {
        if (
            error.code === "SQLITE_CONSTRAINT_UNIQUE" ||
            error.errcode === 2067 ||
            error.message?.includes("UNIQUE constraint failed: users.name")
        ) {
            return res.status(409).json({ error: "NAME_ALREADY_EXISTS" });
        }
        next(error);
    }
});

app.post("/auth/login", (req, res, next) => {
    try {
        const name = requireString(req.body.name, "name");
        const password = requireString(req.body.password, "password");
        const user = db.findUserByName(name);
        if (!user || !bcrypt.compareSync(password, user.password_hash)) {
            return res.status(401).json({ error: "INVALID_CREDENTIALS" });
        }
        const tokens = issueTokenPair(user);
        setAuthCookies(res, tokens);
        return res.json({ user: publicUser(user) });
    } catch (error) {
        next(error);
    }
});

app.post("/auth/refresh", (req, res) => {
    const refreshToken = requireString(
        requestCookies(req)[REFRESH_COOKIE],
        REFRESH_COOKIE,
    );
    const tokenHash = hashRefreshToken(refreshToken);
    const user = db.findUserByRefreshToken(tokenHash);

    if (!user) {
        return res.status(401).json({ error: "REFRESH_TOKEN_INVALID" });
    }

    const tokens = issueTokenPair(user, tokenHash);
    setAuthCookies(res, tokens);
    return res.json({ user: publicUser(user) });
});

app.post("/auth/logout", (req, res) => {
    const refreshToken = requireString(
        requestCookies(req)[REFRESH_COOKIE],
        REFRESH_COOKIE,
    );
    const result = db.revokeRefreshToken(hashRefreshToken(refreshToken));

    if (result.changes === 0) {
        return res.status(401).json({ error: "REFRESH_TOKEN_INVALID" });
    }
    clearAuthCookies(res);
    return res.status(204).send();
});

app.post("/auth/change-password", requireAccessToken, (req, res, next) => {
    try {
        const currentPassword = requireString(
            req.body.currentPassword,
            "currentPassword",
        );
        const newPassword = requireString(req.body.newPassword, "newPassword");
        if (newPassword.length < 8) {
            return res.status(400).json({
                error: "VALIDATION_ERROR",
                message: "newPassword must contain at least 8 characters",
            });
        }

        const user = getUserById(req.user.id);
        if (!bcrypt.compareSync(currentPassword, user.password_hash)) {
            return res.status(401).json({ error: "INVALID_CURRENT_PASSWORD" });
        }

        db.updatePassword(user.id, bcrypt.hashSync(newPassword, 12));
        db.revokeAllRefreshTokens(user.id);
        clearAuthCookies(res);
        return res.status(204).send();
    } catch (error) {
        next(error);
    }
});

app.get("/me", requireAccessToken, (req, res) => {
    res.json({ user: req.user });
});

app.use((error, req, res, next) => {
    if (error.code === "VALIDATION_ERROR") {
        return res
            .status(error.status)
            .json({ error: error.code, message: error.message });
    }
    if (
        error instanceof SyntaxError &&
        error.status === 400 &&
        error.type === "entity.parse.failed"
    ) {
        return res.status(400).json({ error: "INVALID_JSON" });
    }
    console.error(error);
    return res.status(500).json({ error: "INTERNAL_SERVER_ERROR" });
});

if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`Authentication API listening on http://localhost:${PORT}`);
    });
}

module.exports = { app, db };
