/********************************************************************************
 * Copyright (C) 2023 CoCreate and Contributors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 ********************************************************************************/

import { getValueFromObject, dotNotationToObject } from "@cocreate/utils";
import crud from "@cocreate/crud-server";

const organizations = {};

/**
 * Safely converts flexible representations of booleans ("true", "false", 1, 0, "1", "0")
 * into strict boolean values. Returns undefined for non-boolean strings or non-binary numbers.
 *
 * @param {any} value - Value to evaluate.
 * @returns {boolean|undefined} Explicit boolean or undefined if not a boolean literal.
 */
function parseBoolean(value) {
    if (typeof value === "boolean") return value;
    if (typeof value === "number") {
        if (value === 1) return true;
        if (value === 0) return false;
        return undefined;
    }
    if (typeof value === "string") {
        const normalized = value.trim().toLowerCase();
        if (normalized === "true" || normalized === "1") return true;
        if (normalized === "false" || normalized === "0") return false;
    }
    return undefined;
}

if (typeof window !== "undefined") {
    if (crud && typeof crud.listen === "function") {
        crud.listen("object.update", (data) => {
            updateAuthorization(data);
        });

        crud.listen("object.delete", (data) => {
            deleteAuthorization(data);
        });
    }
} else {
    if (typeof process !== "undefined") {
        process.on("crud-event", async (data) => {
            // Safely route deletes vs updates to maintain precise cache sync
            if (data.method === "object.delete") {
                deleteAuthorization(data);
            } else {
                updateAuthorization(data);
            }
        });
    }
}

/**
 * Updates the cached authorization for a specific key within an organization.
 *
 * @param {object} data - The data object containing array, object, and organization_id.
 * @returns {Promise<void>}
 */
async function updateAuthorization(data) {
    const { array, object, organization_id } = data;

    if (array === "keys" && Array.isArray(object) && object.length > 0) {
        const authorization = object[0];

        if (
            authorization &&
            authorization.key &&
            organizations[organization_id] &&
            organizations[organization_id][authorization.key]
        ) {
            // Fetch latest authorization and refresh cache
            const newAuthorization = await readAuthorization(
                authorization.key,
                data
            );
            organizations[organization_id][authorization.key] = newAuthorization;
        }
    }
}

/**
 * Deletes the cached authorization for a specific key within an organization.
 *
 * @param {object} data - The data object containing array, object, and organization_id.
 * @returns {Promise<void>}
 */
async function deleteAuthorization(data) {
    const { array, object, organization_id } = data;

    if (array === "keys" && Array.isArray(object) && object.length > 0) {
        const authorization = object[0];

        if (
            authorization &&
            authorization.key &&
            organizations[organization_id] &&
            organizations[organization_id][authorization.key]
        ) {
            delete organizations[organization_id][authorization.key];
        }
    }
}

/**
 * Retrieves the cached authorization for a specific key within an organization.
 * Safely handles concurrent request promises to avoid race conditions.
 *
 * @param {string} key - The authorization key (e.g., user ID or API key).
 * @param {object} data - The data object containing organization_id.
 * @returns {Promise<object>} A promise that resolves to the authorization details.
 */
async function getAuthorization(key, data) {
    const { organization_id } = data;
    if (!organization_id) return { error: "An organization_id is required" };

    if (!organizations[organization_id]) {
        organizations[organization_id] = {};
    }

    // Cache promise directly to deduplicate concurrent requests for the same key
    if (!organizations[organization_id][key]) {
        organizations[organization_id][key] = readAuthorization(key, data);
    }

    try {
        const resolvedAuth = await organizations[organization_id][key];
        organizations[organization_id][key] = resolvedAuth;
        return resolvedAuth;
    } catch (error) {
        delete organizations[organization_id][key];
        return { error };
    }
}

/**
 * Reads authorization details for a given key and organization.
 * Merges default permissions, key-specific permissions, and associated roles.
 *
 * @param {string} key - The authorization key (e.g., user ID or API key).
 * @param {object} data - Request details containing organization_id and host.
 * @returns {Promise<object>}
 */
async function readAuthorization(key, data) {
    try {
        const { organization_id, host } = data;
        if (!organization_id) return { error: "An organization_id is required" };

        const request = {
            method: "object.read",
            host,
            database: organization_id,
            array: "keys",
            organization_id,
            $filter: {
                query: {
                    $or: key
                        ? [{ default: true }, { default: "true" }, { default: 1 }, { key }]
                        : [{ default: true }, { default: "true" }, { default: 1 }]
                },
                limit: 2
            }
        };

        const authRes = await crud.send(request);

        if (authRes && Array.isArray(authRes.object) && authRes.object.length) {
            const objs = authRes.object;
            const defaultDoc = objs.find((o) => o && parseBoolean(o.default) === true) || {};
            const keyDoc = key ? objs.find((o) => o && o.key === key) : undefined;

            const expandedDefault = dotNotationToObject({}, defaultDoc);
            const expandedKey = keyDoc ? dotNotationToObject({}, keyDoc) : {};
            let authorization = dotNotationToObject(expandedDefault, expandedKey);

            // Set unique roles combination
            const defaultRoles = defaultDoc.roles || [];
            const keyRoles = (keyDoc && keyDoc.roles) || [];
            authorization.roles = Array.from(new Set([...defaultRoles, ...keyRoles]));

            if (!authorization.arrays) authorization.arrays = {};

            // Fetch and merge role permissions if roles exist
            if (authorization.roles.length) {
                const role_ids = authorization.roles
                    .filter(Boolean)
                    .map((_id) => ({ _id }));

                if (role_ids.length > 0) {
                    delete request.$filter;
                    delete request.isFilter;
                    request.object = role_ids;

                    const rolesRes = await crud.send(request);
                    const roles = (rolesRes && rolesRes.object) || [];

                    for (const role of roles) {
                        authorization = dotNotationToObject(authorization, role);
                    }
                }
            }

            return authorization;
        }

        return {};
    } catch (error) {
        console.error("authorization Error", error);
        return { error };
    }
}

/**
 * Validates authorization using user_id first, falling back to apikey.
 * Automatically restores original query filters if present from a previous pass.
 *
 * @param {object} data - Request details including apikey and organization_id.
 * @param {string} user_id - The user ID for validation.
 * @returns {Promise<object|boolean>}
 */
export async function check(data, user_id) {
    // Automatically restore original filter if present from a previous pass
    if (data && data.$filter && data.$filter.original !== undefined) {
        restoreFilter(data);
    }

    let authorization = false;

    if (user_id) {
        authorization = await checkAuthorization({ key: user_id, data });
    }

    if (!authorization || authorization.error) {
        if (data.apikey) {
            authorization = await checkAuthorization({ key: data.apikey, data });
        }
    }

    return authorization;
}

/**
 * Validates whether a key is authorized to perform the action specified in `data`.
 *
 * @param {object} params
 * @param {string} params.key - Key used for authorization (user ID or API key).
 * @param {object} params.data - Request details.
 * @returns {Promise<object|boolean>}
 */
async function checkAuthorization({ key, data }) {
    if (!data.organization_id) return { error: "organization_id is required" };
    if (!data.method) return { error: "method is required" };

    const authorized = await getAuthorization(key, data);

    if (!authorized || authorized.error) return authorized;

    // Verify organization ID scoping
    if (authorized.organization_id && authorized.organization_id !== data.organization_id) {
        return false;
    }

    // Validate host restriction list
    if (Array.isArray(authorized.host) && authorized.host.length > 0) {
        const isAllowedHost =
            authorized.host.includes(data.host) || authorized.host.includes("*");
        if (!isAllowedHost) return false;
    }

    // Direct bypass for admins (handles true, "true", 1, "1")
    if (parseBoolean(authorized.admin) === true) {
        return true;
    }

    // Supports 'methods' as primary, with fallback to legacy 'actions'
    const methods = authorized.methods || authorized.actions;
    if (!methods) {
        return { error: "Authorization does not have any methods or actions defined" };
    }

    const status = await checkMethod(data, methods, data.method);
    if (!status) return false;

    return { authorized: data };
}

/**
 * Matches requested method against authorization rules using hierarchical dot notation.
 * Cascades down specific action hierarchies automatically (e.g. stripe.customers.subscriptions.delete
 * -> stripe.customers.subscriptions -> stripe.customers -> stripe -> *).
 *
 * @param {object} data - Request data.
 * @param {object} authorized - Authorization methods tree.
 * @param {string} method - Method string (e.g. "stripe.customers.post" or "object.read").
 * @returns {Promise<boolean>}
 */
async function checkMethod(data, authorized, method) {
    if (!authorized || typeof authorized !== "object") return false;

    // 1. Direct match on exact path (handles both flat dot-notated keys and deep object paths)
    const directMatch = getValueFromObject(authorized, method) ?? authorized[method];
    if (directMatch !== undefined) {
        return await checkMethodMatch(data, directMatch, method);
    }

    // 2. Cascading match up dot-notation hierarchy (e.g. "stripe.customers.post" -> "stripe.customers" -> "stripe")
    if (method.includes(".")) {
        const parts = method.split(".");
        while (parts.length > 1) {
            parts.pop();
            const parentPath = parts.join(".");
            const parentMatch = getValueFromObject(authorized, parentPath) ?? authorized[parentPath];
            if (parentMatch !== undefined) {
                return await checkMethodMatch(data, parentMatch, parentPath);
            }
        }
    }

    // 3. Fallback to global wildcard "*"
    if (authorized["*"] !== undefined) {
        return await checkMethodMatch(data, authorized["*"], "*");
    }

    return false;
}

/**
 * Evaluates authorization rules and applies field-level sanitization when $keys rules exist.
 *
 * @param {object} data - Input payload.
 * @param {boolean|string|number|object|Array} authorized - Permission rule definition.
 * @param {string} match - Current method match key.
 * @returns {Promise<boolean>}
 */
async function checkMethodMatch(data, authorized, match) {
    // Evaluate explicit boolean/numeric/string booleans first
    const boolVal = parseBoolean(authorized);
    if (boolVal !== undefined) {
        return boolVal;
    }

    // String permission rule match
    if (typeof authorized === "string") {
        return authorized === match;
    }

    let status = false;
    const newmatch = data.method.startsWith(match + ".")
        ? data.method.slice(match.length + 1)
        : "";

    const rawKeys = [];

    if (Array.isArray(authorized)) {
        for (const rule of authorized) {
            const ruleStatus = await checkMethodMatch(data, rule, newmatch || match);
            if (ruleStatus === true) status = true;
        }
    } else if (typeof authorized === "object" && authorized !== null) {
        for (const key of Object.keys(authorized)) {
            if (key.startsWith("$")) {
                if (["$storage", "$database", "$array", "$index"].includes(key)) {
                    const opStatus = await checkMethodOperators(data, key, authorized[key]);
                    if (typeof opStatus === "boolean") status = opStatus;
                } else if (key === "$keys") {
                    const type = data.method.split(".")[0];
                    if (data[type]) {
                        rawKeys.push(authorized[key]);
                    }
                } else {
                    const filterStatus = applyFilter(data, authorized[key], key);
                    if (filterStatus) status = true;
                }
            }
        }
    }

    // Process field sanitization if $keys definitions were encountered
    if (rawKeys.length > 0) {
        const { inclusion, exclusion } = parsePermissions(rawKeys);
        if (inclusion || exclusion) {
            const type = data.method.split(".")[0];
            if (data[type]) {
                data[type] = sanitizeData(data[type], inclusion, exclusion);
                status = true;
            }
        }
    }

    // Check nested fallback matches (* or exact remaining path)
    if (newmatch && !status && typeof authorized === "object" && authorized !== null) {
        if (authorized[newmatch] !== undefined) {
            status = await checkMethodMatch(data, authorized[newmatch], newmatch);
        } else if (authorized["*"] !== undefined) {
            status = await checkMethodMatch(data, authorized["*"], newmatch);
        }
    }

    return status;
}

/**
 * Dynamic operator evaluation ($storage, $database, $array, $index).
 */
async function checkMethodOperators(data, key, authorization) {
    try {
        if (authorization === "$user_id") {
            authorization = (data.socket && data.socket.user_id) || data.user_id;
            if (!authorization) return false;
        }

        if (key.startsWith("$")) {
            const type = key.substring(1);

            if (!data[type]) return undefined;

            if (typeof data[type] === "string") {
                return checkAuthorizationData(data, authorization, data[type]);
            }

            if (Array.isArray(data[type])) {
                if (!data[type].length) return undefined;

                let allAuthorized = true;
                for (let i = 0; i < data[type].length; i++) {
                    const itemData = typeof data[type][i] === "object" && data[type][i] !== null
                        ? data[type][i].name
                        : data[type][i];

                    const authResult = checkAuthorizationData(data, authorization, itemData);
                    if (authResult === false) return false;
                    if (authResult === undefined) allAuthorized = undefined;
                }
                return allAuthorized;
            }

            if (typeof data[type] === "object" && data[type] !== null) {
                return checkAuthorizationData(data, authorization, data[type].name);
            }
        }

        return undefined;
    } catch (e) {
        console.error("Operator Check Error:", e);
        return undefined;
    }
}

/**
 * Checks authorization rule match for a given key string/array/object.
 */
function checkAuthorizationData(data, authorization, key) {
    if (typeof authorization === "string") {
        return key === authorization ? true : undefined;
    }

    if (Array.isArray(authorization)) {
        return authorization.includes(key) ? true : undefined;
    }

    if (typeof authorization === "object" && authorization !== null) {
        if (typeof authorization[key] === "object" && authorization[key] !== null) {
            for (const queryKey of Object.keys(authorization[key])) {
                return applyFilter(data, authorization[key], queryKey);
            }
        }

        // Safely evaluate flexible booleans ("false", "0", 0, "true", 1, true, false)
        const boolVal = parseBoolean(authorization[key]);
        if (boolVal !== undefined) return boolVal;
    }

    return undefined;
}

/**
 * Appends query conditions to request payload filter object.
 * Preserves original query in data.$filter.original and wraps conditions safely in $and.
 * Replaces $user_id token with active session or user ID.
 */
function applyFilter(data, authorization, authorizationKey) {
    const keyParts = authorizationKey.split(".");
    const operator = keyParts.pop();
    const key = keyParts.join(".");

    const supportedOperators = [
        "$eq", "$ne", "$lt", "$lte", "$gt", "$gte", "$in", "$nin",
        "$or", "$and", "$not", "$nor", "$exists", "$type", "$mod",
        "$regex", "$text", "$where", "$all", "$elemMatch", "$size"
    ];

    if (supportedOperators.includes(operator)) {
        if (!data.$filter) data.$filter = { query: {} };
        if (!data.$filter.query) data.$filter.query = {};

        // Preserve client's original filter before applying security constraints
        if (!data.$filter.original) {
            data.$filter.original = JSON.parse(JSON.stringify(data.$filter.query));
        }

        let value = typeof authorization === "string" ? authorization : authorization[authorizationKey];
        
        // Resolve $user_id dynamically from socket session or request body
        if (value === "$user_id") {
            value = (data.socket && data.socket.user_id) || data.user_id;
            // Prevent unauthenticated undefined tokens from matching undefined fields
            if (!value) return false;
        }

        const securityConstraint = { [key]: { [operator]: value } };

        // Wrap existing client query and security constraint together with top-level $and
        if (Object.keys(data.$filter.query).length === 0) {
            data.$filter.query = securityConstraint;
        } else if (Array.isArray(data.$filter.query.$and)) {
            data.$filter.query.$and.push(securityConstraint);
        } else {
            data.$filter.query = {
                $and: [
                    data.$filter.query,
                    securityConstraint
                ]
            };
        }

        return true;
    }
    return false;
}

/**
 * Restores original client $filter.query from data.$filter.original backup.
 * Internal helper automatically invoked at the start of check() on pass 2.
 *
 * @param {object} data - The request data object.
 * @returns {boolean} True if filter was restored, false otherwise.
 */
function restoreFilter(data) {
    if (data && data.$filter && data.$filter.original !== undefined) {
        data.$filter.query = JSON.parse(JSON.stringify(data.$filter.original));
        delete data.$filter.original;
        return true;
    }
    return false;
}

/**
 * Parses raw $keys permission entries into inclusion or exclusion lists.
 * Prioritizes inclusions over exclusions.
 */
function parsePermissions(authorization) {
    const inclusion = [];
    const exclusion = [];

    function processPermission(entry) {
        if (typeof entry === "string") {
            inclusion.push(entry);
        } else if (typeof entry === "object" && entry !== null) {
            for (const [key, value] of Object.entries(entry)) {
                const boolVal = parseBoolean(value);
                if (boolVal === true) inclusion.push(key);
                else if (boolVal === false) exclusion.push(key);
            }
        }
    }

    const permissionEntries = Array.isArray(authorization)
        ? authorization
        : (authorization ? [authorization] : []);

    permissionEntries.forEach(processPermission);

    if (inclusion.length > 0) {
        return { inclusion, exclusion: null };
    } else if (exclusion.length > 0) {
        return { inclusion: null, exclusion };
    }

    return { inclusion: null, exclusion: null };
}

/**
 * Sanitizes object/array payloads according to inclusion/exclusion permission rules.
 */
function sanitizeData(data, inclusion, exclusion) {
    if (inclusion === null && exclusion === null) {
        return data;
    }

    if (Array.isArray(data)) {
        return data.map((item) => sanitizeData(item, inclusion, exclusion));
    }

    if (typeof data === "object" && data !== null) {
        let sanitized = {};

        if (inclusion) {
            for (let i = 0; i < inclusion.length; i++) {
                const inclusionData = generateDotNotation(data, inclusion[i]);
                sanitized = { ...sanitized, ...inclusionData };
            }
            return dotNotationToObject(sanitized);
        } else if (exclusion) {
            for (let i = 0; i < exclusion.length; i++) {
                const exclusionData = generateDotNotation(data, exclusion[i], true);
                sanitized = { ...sanitized, ...exclusionData };
            }
            return dotNotationToObject(sanitized, data);
        }
    }

    return data;
}

/**
 * Extracts dot-notation paths from target data without mutating keys parameter.
 */
function generateDotNotation(data, path, isExclusion = false) {
    if (typeof path !== "string") throw new Error("Path must be a string");

    const result = {};

    function processKeys(dataItem, keys, index, prefix) {
        if (dataItem === undefined) return;

        if (index >= keys.length) {
            result[prefix] = isExclusion ? undefined : dataItem;
            return;
        }

        let key = keys[index];
        const isArray = key.endsWith("[]");
        if (isArray) key = key.slice(0, -2);

        const currentPrefix = prefix ? `${prefix}.${key}` : key;
        const currentData = getValueFromObject(dataItem, key);

        if (isArray && Array.isArray(currentData)) {
            currentData.forEach((item, i) => {
                processKeys(item, keys, index + 1, `${currentPrefix}[${i}]`);
            });
        } else if (!isArray && currentData !== undefined) {
            processKeys(currentData, keys, index + 1, currentPrefix);
        }
    }

    if (data && path.trim()) {
        const keys = path.split(".");
        processKeys(data, keys, 0, "");
    }

    return result;
}

export { check };