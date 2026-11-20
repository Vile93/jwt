const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const tempDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "jwt-auth-"));
const databaseFile = path.join(tempDirectory, "integration.sqlite");
process.env.JWT_SECRET = "integration-test-secret-that-is-long-enough";
process.env.DATABASE_FILE = databaseFile;
process.env.NODE_ENV = "test";

const { app, db } = require("../../server");

let server;
let baseUrl;

test.before(async () => {
    await new Promise((resolve) => {
        server = app.listen(0, "127.0.0.1", resolve);
    });
    baseUrl = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    db.close();
    fs.rmSync(tempDirectory, { recursive: true, force: true });
});

function cookieFrom(response, name) {
    const setCookies =
        typeof response.headers.getSetCookie === "function"
            ? response.headers.getSetCookie()
            : [];

    for (const setCookie of setCookies) {
        const pair = setCookie.split(";")[0];
        if (pair.startsWith(`${name}=`)) {
            return pair;
        }
    }
    return null;
}

async function request(method, route, options = {}) {
    return fetch(`${baseUrl}${route}`, {
        method,
        headers: {
            "content-type": "application/json",
            ...(options.headers || {}),
        },
        body: options.body ? JSON.stringify(options.body) : undefined,
    });
}

async function registerAndLogin(name) {
    const registerResponse = await request("POST", "/auth/register", {
        body: { name, password: "password123" },
    });
    assert.equal(registerResponse.status, 201);

    const loginResponse = await request("POST", "/auth/login", {
        body: { name, password: "password123" },
    });
    assert.equal(loginResponse.status, 200);

    const accessCookie = cookieFrom(loginResponse, "access_token");
    const refreshCookie = cookieFrom(loginResponse, "refresh_token");
    assert.ok(accessCookie);
    assert.ok(refreshCookie);
    return { accessCookie, refreshCookie };
}

test("registration validates input, creates users, and rejects duplicates", async () => {
    const invalid = await request("POST", "/auth/register", {
        body: { name: "short", password: "123" },
    });
    assert.equal(invalid.status, 400);

    const first = await request("POST", "/auth/register", {
        body: { name: "integration-user", password: "password123" },
    });
    assert.equal(first.status, 201);

    const duplicate = await request("POST", "/auth/register", {
        body: { name: "integration-user", password: "password123" },
    });
    assert.equal(duplicate.status, 409);
});

test("login rejects invalid credentials", async () => {
    await request("POST", "/auth/register", {
        body: { name: "invalid-login", password: "password123" },
    });
    const response = await request("POST", "/auth/login", {
        body: { name: "invalid-login", password: "wrong-password" },
    });
    assert.equal(response.status, 401);
    assert.equal((await response.json()).error, "INVALID_CREDENTIALS");
});

test("access cookie authorizes /me", async () => {
    const cookies = await registerAndLogin("me-user");
    const response = await request("GET", "/me", {
        headers: { cookie: cookies.accessCookie },
    });

    assert.equal(response.status, 200);
    const payload = await response.json();
    assert.equal(payload.user.name, "me-user");
});

test("refresh rotates the refresh token and rejects the old token", async () => {
    const cookies = await registerAndLogin("refresh-user");
    const refresh = await request("POST", "/auth/refresh", {
        headers: { cookie: cookies.refreshCookie },
    });

    assert.equal(refresh.status, 200);
    const newRefreshCookie = cookieFrom(refresh, "refresh_token");
    assert.ok(newRefreshCookie);
    assert.notEqual(newRefreshCookie, cookies.refreshCookie);

    const oldRefresh = await request("POST", "/auth/refresh", {
        headers: { cookie: cookies.refreshCookie },
    });
    assert.equal(oldRefresh.status, 401);
});

test("logout revokes the refresh session", async () => {
    const cookies = await registerAndLogin("logout-user");
    const logout = await request("POST", "/auth/logout", {
        headers: { cookie: cookies.refreshCookie },
    });
    assert.equal(logout.status, 204);

    const refresh = await request("POST", "/auth/refresh", {
        headers: { cookie: cookies.refreshCookie },
    });
    assert.equal(refresh.status, 401);
});

test("password change succeeds and revokes refresh sessions", async () => {
    const cookies = await registerAndLogin("password-user");
    const change = await request("POST", "/auth/change-password", {
        headers: {
            cookie: `${cookies.accessCookie}; ${cookies.refreshCookie}`,
        },
        body: {
            currentPassword: "password123",
            newPassword: "new-password123",
        },
    });
    assert.equal(change.status, 204);

    const oldRefresh = await request("POST", "/auth/refresh", {
        headers: { cookie: cookies.refreshCookie },
    });
    assert.equal(oldRefresh.status, 401);

    const login = await request("POST", "/auth/login", {
        body: { name: "password-user", password: "new-password123" },
    });
    assert.equal(login.status, 200);
});

/* test("failed test", () => {
    assert.equal(1, 2);
}); */
