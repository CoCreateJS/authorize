# @cocreate/authorize

A high-performance, real-time multi-tenant authorization framework, permission evaluation engine, and data sanitization firewall. Scoped entirely to single-tenant memory landscapes using an ESM singleton cache layer (`organizations`), this engine interprets granular database-backed action matrices, handles recursive role inheritance, applies dynamic query filter injections, and runs deep field-level payload sanitization (inclusions and exclusions) to enforce bulletproof access controls across distributed networks.

---

## Table of Contents

* [Features](#features)
* [Dynamic Rule Operators](#dynamic-rule-operators)
* [Installation](#installation)
* [Usage](#usage)
* [How it Works](#how-it-works)
* [Third-Party & REST API Permissions](#third-party--rest-api-permissions)
* [Architecture and Payload Specs](#architecture-and-payload-specs)
* [Security & Sanitization Firewall](#security--sanitization-firewall)
* [How to Contribute](#how-to-contribute)
* [License](#license)

---

## Features

* **Multi-Tenant Memory Caching:** Maintains isolated authorization indices in-memory (`organizations`), matching active requests instantly without generating endless round-trip database lookup overhead.
* **Reactive Event-Driven Cache Invalidation:** Plugs into client and server CRUD listener matrices (`object.update`, `object.delete`), automatically performing hot cache updates or targeted purging whenever authorization keys are modified.
* **Hierarchical Dot-Notation Routing:** Cascades down specific action hierarchies automatically (e.g., checking permission for `stripe.customers.subscriptions.delete` will seamlessly fall back to `stripe.customers` or `stripe` or `*` global wildcards if explicit rules aren't found).
* **Deep Role Inheritance & Merging:** Compiles comprehensive baseline configurations by fetching assigned collection roles, dynamically transforming flat dot-notated entries into deep-merged privilege trees.
* **Dynamic Query Filter Injections:** Injects complex MongoDB-style query filters (`$eq`, `$ne`, `$in`, etc.) directly into outgoing execution targets based on tenant permission configurations (e.g., locking access bounds to active user states).
* **Payload Field Sanitization Firewall:** Segregates input and output object surfaces by evaluating raw arrays against strict field permissions, filtering properties instantly using absolute priority inclusion or exclusion logic.

---

## Dynamic Rule Operators

The engine reads specific evaluation tokens within your permission definitions to perform inline data injection and structural assertions:

| Core Rule Operator | Action Evaluation & Resolution |
| --- | --- |
| **`$user_id`** | Resolves dynamically against session properties, pulling the verified user ID from active socket or request configurations. |
| **`$storage` / `$database`** | Intercepts validation cycles, checking incoming parameters explicitly against target database partitions. |
| **`$array` / `$index`** | Scans collection array parameters dynamically to verify target indices or resource keys align with tenant scopes. |
| **`$keys`** | Triggers the field-level data sanitization firewall, identifying fields allowed for reading/writing. |
| **`filter`** | Enforces row-level constraints by modifying the active request query with runtime operators. |

---

## Installation

```bash
npm install @cocreate/authorize
```

---

## Usage

### Programmatic Authorization Check

Evaluate a user session or API key against an incoming execution request. The engine processes the user credential first and gracefully falls back to the payload API key if necessary:

```javascript
import { check } from '@cocreate/authorize';

const requestPayload = {
  organization_id: "64b9a32e18f21bc56789abcd",
  method: "object.read.profile",
  host: "app.cocreate.js",
  apikey: "cc-sk-live-90210xfdsa...",
  // Targets to evaluate/sanitize
  object: {
    name: "user-profiles",
    secretField: "sensitive-data",
    publicField: "hello world"
  }
};

const activeUserId = "64b9a35f18f21bc5e9812456";

// Evaluates permissions, handles inheritance, and optimizes payload properties inline
const evaluationResult = await check(requestPayload, activeUserId);

if (evaluationResult === false) {
  console.log("Access Denied: Unauthorized operation.");
} else {
  console.log("Authorized payload (sanitized):", evaluationResult.authorized);
}
```

### Manual Authorization Fetching

Manually extract a tenant's fully compiled, role-inherited authorization profile from the cache layer or database:

```javascript
import { getAuthorization } from '@cocreate/authorize';

const queryContext = {
  organization_id: "64b9a32e18f21bc56789abcd",
  host: "app.cocreate.js"
};

const targetKey = "64b9a35f18f21bc5e9812456"; // User ID or API Key string

const fullAuthProfile = await getAuthorization(targetKey, queryContext);
console.log(fullAuthProfile);
/* 
Outputs compiled configuration (Note: 'methods' is primary, 'actions' supported for legacy):
{
  _id: "...",
  key: "64b9a35f18f21bc56789abcd",
  organization_id: "64b9a32e18f21bc56789abcd",
  admin: false,
  roles: ["manager", "employee"],
  methods: {
    "object.read": true,
    "object.write": { "$keys": { "secretField": false } }
  }
}
*/
```

---

## How it Works

1. **Context Interception & Fallback:** The execution pipeline enters through `check()`. The framework initializes checking structures against the explicit `user_id` context. If the resolution returns `false` or errors out, it intercepts request metrics and retries using `data.apikey`.
2. **Deterministic Cache Evaluation:** `getAuthorization()` checks if the target `organization_id` profile exists in memory. If absent, it issues a database query through the CRUD gateway (`readAuthorization`) to pull both default configurations (`default: true`) and key-specific rules concurrently.
3. **Role Expansion & Deep Merging:** The engine reads the fetched rules, maps associated arrays via `dotNotationToObject`, gathers any assigned structural roles (`roles`), and issues secondary pipelines to retrieve each role profile. It then executes deep-merging loops to fold role rules into a single authorization blueprint.
4. **Hierarchical Action Mapping:** When validating actions via `checkMethod()`, the system checks `methods` (or legacy `actions`) and performs full string match scans. If missing, it systematically splits the action parameter across period boundaries (e.g., `stripe.customers.subscriptions.delete` → `stripe.customers.subscriptions` → `stripe.customers` → `stripe` → `*`), climbing up the matrix to find an applicable rule block.
5. **Dynamic Filter Injection:** If rule evaluations match parameter queries, `applyFilter()` isolates operators like `$eq` or `$ne`. It automatically maps contextual criteria (such as shifting `$user_id` into the user's active session ID) and transforms the target query structure directly while backing up `data.filter.original`.
6. **Payload Cleansing & Automatic Filter Restoration:** Fields pass through `parsePermissions()` to filter out restricted parameters via `sanitizeData()`. On pass 2 (outbound sanitization), `check()` automatically restores the original query filter before dispatch.

---

## Third-Party & REST API Permissions

When configuring permissions for external APIs (e.g., Stripe, SendGrid), endpoints are converted into dot-notation method strings using the pattern:

`Namespace -> Path -> Verb`

* **`POST /customers`** → `"stripe.customers.post"`
* **`DELETE /customers/subscriptions`** → `"stripe.customers.subscriptions.delete"`

```javascript
export const stripePermissions = {
  "methods": {
    "stripe": {
      // Endpoint-level grant: automatically allows GET, POST, and DELETE on payment_intents
      "payment_intents": true,

      // Verb-level restriction with payload field sanitization
      "customers": {
        "get": true,
        "post": {
          "$keys": {
            "email": true,
            "name": true,
            "metadata": true,
            "ssn": false // Explicitly strip SSN field from Stripe requests
          }
        },
        // Deep sub-path route endpoint: "DELETE /customers/subscriptions"
        "subscriptions": {
          "delete": true
        }
      },

      // Complete endpoint block
      "refunds": {
        "post": false
      }
    }
  }
};
```

---

## Architecture and Payload Specs

### Check Parameter Schema

The framework expects standard transaction blocks containing routing properties and environmental identifiers:

| Field Element | Type | Role |
| --- | --- | --- |
| `organization_id` | `String` | **Required.** Anchors the request context to isolated tenant databases. |
| `method` | `String` | **Required.** The namespace path of the active request (e.g., `"object.write.users"` or `"stripe.customers.subscriptions.delete"`). |
| `host` | `String` | Environmental host context checked against explicit key domain limitations. |
| `apikey` | `String` | Authentication token utilized as a fallback routing vector if no explicit user context exists. |
| `object` | `Object|Array` | The primary data payload structural container undergoing field-level sanitization. |

---

## Security & Sanitization Firewall

> Inclusion rules always take absolute priority over exclusion boundaries. If an authorization entry contains even one explicit `true` attribute mapping inside its field specification array, all other sister fields are immediately treated as restricted and stripped.

### Sanitization Prioritization Logic

The module routes all calculated configurations through an isolated evaluation step to determine how properties are processed:

```javascript
if (inclusion.length > 0) {
    // If any explicit inclusion exists, exclusions are entirely ignored
    return { inclusion, exclusion: null };
} else if (exclusion.length > 0) {
    // If only exclusions exist, inclusions remain null
    return { inclusion: null, exclusion };
}
```

* **Inclusion Mode:** Keeps *only* the specific fields matching dot-notation rules exactly (e.g. `profile.name`). All unspecified object fields are stripped.
* **Exclusion Mode:** Preserves the entire object surface area *except* the properties explicitly blacklisted (e.g. mapping a field to `false` or `undefined`), which are completely expunged before returning.

---

## How to Contribute

We encourage contribution to our libraries, please see our [CONTRIBUTING.md](https://github.com/CoCreateJS/authorize/blob/master/CONTRIBUTING.md) guide for details. If you encounter any bugs or wish to make feature requests, please submit an issue on our [GitHub Issues](https://github.com/CoCreateJS/authorize/issues) tracker.

For broader system configurations and API guides, please visit our [CoCreate Authorization Documentation](https://cocreatejs.com/docs/authorize).

---

## License

This software is dual-licensed under the GNU Affero General Public License version 3 (AGPLv3) and a commercial license.
## Authorized request helper

`await authorize.request(envelope, user_id?)` calls the service's `check()` method and returns the sanitized execution envelope without its transport `apikey`. It snapshots organization, host, method, API, endpoint and array before checking, then rejects any changes to those targets, including in-place mutations. Denials and malformed authorization results throw an error with `code: 'AUTHORIZATION_DENIED'`; authorization service errors propagate to the caller.

Modules own their entrances and decide when to call this helper after resolving resource context. Credential verification, HTTP parsing, webhook signature verification and trusted internal execution stay with their respective services. Existing `check()` behavior is unchanged.


Authorization reads all matching default keys and the supplied key without a
result limit. Every default contributes to the existing configuration merge;
roles from every default and the supplied key are deduplicated before lookup.
Explicit values continue to override normally, including `admin: false`. Omit
`admin` from defaults unless the override is intended; non-admin access does not
require an explicit false value.
