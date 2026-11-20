const { DatabaseSync } = require("node:sqlite");

class Db {
    constructor(filename) {
        this.database = new DatabaseSync(filename);
        this.database.exec("PRAGMA journal_mode = WAL");
        this.database.exec("PRAGMA foreign_keys = ON");
        this.createTables();
    }

    createTables() {
        this.database.exec(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                roles_json TEXT NOT NULL DEFAULT '["user"]'
            );

            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at INTEGER NOT NULL,
                revoked_at INTEGER,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `);
    }

    createUser(name, passwordHash) {
        const result = this.database
            .prepare(
                `
                INSERT INTO users (name, password_hash, roles_json)
                VALUES (?, ?, ?)
            `,
            )
            .run(name, passwordHash, '["user"]');

        return this.findUserById(result.lastInsertRowid);
    }

    findUserById(id) {
        return this.database
            .prepare("SELECT * FROM users WHERE id = ?")
            .get(id);
    }

    findUserByName(name) {
        return this.database
            .prepare("SELECT * FROM users WHERE name = ?")
            .get(name);
    }

    findUserByRefreshToken(tokenHash) {
        return this.database
            .prepare(
                `
                SELECT users.* FROM users
                INNER JOIN refresh_tokens
                    ON refresh_tokens.user_id = users.id
                WHERE refresh_tokens.token_hash = ?
                  AND refresh_tokens.revoked_at IS NULL
                  AND refresh_tokens.expires_at > ?
            `,
            )
            .get(tokenHash, Date.now());
    }

    createRefreshToken(userId, tokenHash, expiresAt) {
        this.database
            .prepare(
                `
                INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
                VALUES (?, ?, ?)
            `,
            )
            .run(userId, tokenHash, expiresAt);
    }

    revokeRefreshToken(tokenHash) {
        return this.database
            .prepare(
                `
                UPDATE refresh_tokens
                SET revoked_at = ?
                WHERE token_hash = ? AND revoked_at IS NULL
            `,
            )
            .run(Date.now(), tokenHash);
    }

    updatePassword(userId, passwordHash) {
        return this.database
            .prepare(
                `
                UPDATE users
                SET password_hash = ?
                WHERE id = ?
            `,
            )
            .run(passwordHash, userId);
    }

    revokeAllRefreshTokens(userId) {
        return this.database
            .prepare(
                `
                UPDATE refresh_tokens
                SET revoked_at = ?
                WHERE user_id = ? AND revoked_at IS NULL
            `,
            )
            .run(Date.now(), userId);
    }

    close() {
        this.database.close();
    }
}

module.exports = Db;
