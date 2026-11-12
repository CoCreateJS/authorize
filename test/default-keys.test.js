import assert from 'node:assert/strict';
import test from 'node:test';
import { crudServer } from '@cocreate/crud/server';
import { check } from '../src/index.js';

function fixture(t, organization_id, documents, roles = []) {
    const requests = [];
    t.mock.method(crudServer, 'send', async request => {
        requests.push(structuredClone(request));
        if (!request.filter) return { object: structuredClone(roles) };
        const limit = request.filter.limit;
        return { object: structuredClone(limit ? documents.slice(0, limit) : documents) };
    });
    return { requests, payload: { method: 'object.read', organization_id, apikey: `test-${organization_id}` } };
}

test('multiple default records cannot exclude the supplied admin key', async t => {
    const org = 'default-admin-regression';
    const { requests, payload } = fixture(t, org, [
        { default: true, organization_id: org, 'methods.object.read': false },
        { default: 'true', organization_id: org, 'methods.object.read': false },
        { key: `test-${org}`, organization_id: org, admin: true }
    ]);
    assert.equal(await check(payload), true);
    assert.equal(requests[0].filter.limit, undefined);
    assert.ok(requests[0].filter.query.$or.some(query => query.key === payload.apikey));
});

test('all default permissions and role references are merged with the supplied key', async t => {
    const org = 'default-merge-regression';
    const { requests, payload } = fixture(t, org, [
        { default: true, organization_id: org, 'methods.object.read': true, roles: ['role-one'] },
        { default: 1, organization_id: org, 'methods.object.update': true, roles: ['role-two', 'role-one'] },
        { key: `test-${org}`, organization_id: org, 'methods.object.delete': true, roles: ['role-three'] }
    ], [{}]);
    for (const method of ['object.read', 'object.update', 'object.delete']) {
        const request = { ...payload, method };
        assert.equal((await check(request)).authorized, request);
    }
    assert.deepEqual(requests[1].object, [{ _id: 'role-one' }, { _id: 'role-two' }, { _id: 'role-three' }]);
    assert.equal(requests.length, 2, 'The merged authorization is cached after loading keys and roles');
});

test('requests without a supplied key merge every default', async t => {
    const org = 'anonymous-default-regression';
    const { payload } = fixture(t, org, [
        { default: true, organization_id: org, 'methods.object.read': true },
        { default: 'true', organization_id: org, 'methods.object.update': true }
    ]);
    delete payload.apikey;
    for (const method of ['object.read', 'object.update']) {
        const request = { ...payload, method };
        assert.equal((await check(request)).authorized, request);
    }
});

test('explicit admin false remains a configured override', async t => {
    const org = 'configured-admin-override';
    const { payload } = fixture(t, org, [
        { default: true, organization_id: org, admin: false, 'methods.object.read': false },
        { key: `test-${org}`, organization_id: org, admin: true }
    ]);
    assert.equal(await check(payload), false);
});
