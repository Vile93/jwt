const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const Db = require("../../db");

function createDb() {
    return new Db(":memory:");
}

test("Db.createUser stores a user and find methods return it", () => {
    const db = createDb();
    try {
        const passwordHash = "bcrypt-password-hash";
        const user = db.createUser("unit-user", passwordHash);

        assert.equal(user.name, "unit-user");
        assert.equal(user.password_hash, passwordHash);
        assert.deepEqual(JSON.parse(user.roles_json), ["user"]);
        assert.deepEqual(db.findUserByName("unit-user"), user);
        assert.deepEqual(db.findUserById(user.id), user);
    } finally {
        db.close();
    }
});

test("Db rejects duplicate usernames", () => {
    const db = createDb();
    try {
        db.createUser("duplicate", "hash-1");
        assert.throws(
            () => db.createUser("duplicate", "hash-2"),
            (error) =>
                error.code === "SQLITE_CONSTRAINT_UNIQUE" ||
                error.message.includes("UNIQUE constraint failed"),
        );
    } finally {
        db.close();
    }
});

test("Db refresh-token lifecycle creates, finds, rotates, and revokes tokens", () => {
    const db = createDb();
    try {
        const user = db.createUser("token-user", "hash");
        const firstHash = crypto
            .createHash("sha256")
            .update("first-refresh-token")
            .digest("hex");
        const secondHash = crypto
            .createHash("sha256")
            .update("second-refresh-token")
            .digest("hex");

        db.createRefreshToken(user.id, firstHash, Date.now() + 60_000);
        assert.equal(db.findUserByRefreshToken(firstHash).id, user.id);

        assert.equal(db.revokeRefreshToken(firstHash).changes, 1);
        assert.equal(db.findUserByRefreshToken(firstHash), undefined);

        db.createRefreshToken(user.id, secondHash, Date.now() + 60_000);
        assert.equal(db.revokeAllRefreshTokens(user.id).changes, 1);
        assert.equal(db.findUserByRefreshToken(secondHash), undefined);
    } finally {
        db.close();
    }
});

test("Db.updatePassword changes the stored password hash", () => {
    const db = createDb();
    try {
        const user = db.createUser("password-user", "old-hash");
        db.updatePassword(user.id, "new-hash");
        assert.equal(db.findUserById(user.id).password_hash, "new-hash");
    } finally {
        db.close();
    }
});

test("Db.createUser returns roles as an array", () => {
    const db = createDb();

    try {
        const user = db.createUser("roles-user", "hash");

        assert.deepEqual(user.roles, ["user"]);
    } finally {
        db.close();
    }
});
