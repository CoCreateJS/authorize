import assert from 'node:assert/strict';
import test from 'node:test';
import { crudServer } from '@cocreate/crud/server';
import { check, request } from '../src/index.js';
import keys from '../../../CoCreate-app/src/apps/api-keys/config/data.json' with { type: 'json' };

test('a managed credential is restricted to its assigned tenant', async t => {
    t.mock.method(crudServer, 'send', async () => ({ object: [{ key: 'managed-scope-key', managedOrganization: 'tenant',
        organization_id: 'scope-platform', methods: { workflow: { createOrganizationServer: true } } }] }));
    const payload = { method: 'workflow.createOrganizationServer', organization_id: 'scope-platform', host: 'platform.test',
        managedOrganization: 'tenant', apikey: 'managed-scope-key' };
    assert.ok(await check({ ...payload }));
    const authorized = await request({ ...payload });
    assert.equal(authorized.managedOrganization, 'tenant');
    assert.equal(authorized.apikey, undefined);
    for (const managedOrganization of ['other', undefined]) {
        await assert.rejects(request({ ...payload, managedOrganization }), { code: 'AUTHORIZATION_DENIED' });
    }
});

test('authorization cannot rewrite the managed tenant reference', async () => {
    const payload = { method: 'workflow.createOrganizationServer', organization_id: 'platform', managedOrganization: 'tenant' };
    await assert.rejects(request.call({ check: async () => ({ authorized: { ...payload, managedOrganization: 'other' } }) }, payload),
        { code: 'AUTHORIZATION_DENIED' });
});

test('the seeded managed role grants both parent workflows only within the assigned tenant', async t => {
    const role = keys.object.find(record => record._id === '6b0700000000000000000021');
    t.mock.method(crudServer, 'send', async query => ({ object: query.filter
        ? [{ key: 'workflow-role-key', organization_id: 'role-platform', managedOrganization: 'tenant', roles: [role._id] }]
        : [role] }));
    for (const name of ['createOrganizationServer', 'deleteOrganizationServer']) {
        const payload = { method: `workflow.${name}`, organization_id: 'role-platform', host: 'platform.test',
            managedOrganization: 'tenant', apikey: 'workflow-role-key' };
        assert.equal((await request({ ...payload })).method, payload.method);
        await assert.rejects(request({ ...payload, managedOrganization: 'other' }), { code: 'AUTHORIZATION_DENIED' });
    }
});
