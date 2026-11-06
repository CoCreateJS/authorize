import { test } from 'node:test';
import assert from 'node:assert/strict';
import crud from '@cocreate/crud-server';
import { check } from '../src/index.js';

function authorizationDocument(key) {
    return {
        key,
        organization_id: 'org',
        methods: {
            'object.read': { '$storage': '$user_id' }
        }
    };
}

test('user ID rules use the trusted check argument without data.socket', async t => {
    t.mock.method(crud, 'send', async request => ({
        object: [authorizationDocument(request.filter.query.$or[1]?.key || 'trusted-user')]
    }));

    const data = {
        method: 'object.read',
        organization_id: 'org',
        storage: 'trusted-user',
        user_id: 'message-sender'
    };
    const result = await check(data, 'trusted-user');

    assert.equal(result.authorized, data);
    assert.equal(data.user_id, 'message-sender');
    assert.equal('socket' in data, false);
});

test('nested $user_id filters use the trusted check argument without changing data.user_id', async t => {
    t.mock.method(crud, 'send', async request => ({
        object: [{
            key: 'trusted-filter-user',
            organization_id: 'org',
            methods: {
                'object.read': {
                    '$storage': {
                        users: { 'filter.query.owner_id.$eq': '$user_id' }
                    }
                }
            }
        }]
    }));

    const data = {
        method: 'object.read',
        organization_id: 'org',
        storage: 'users',
        user_id: 'message-sender'
    };
    const result = await check(data, 'trusted-filter-user');

    assert.equal(result.authorized, data);
    assert.equal(data.filter.query['filter.query.owner_id'].$eq, 'trusted-filter-user');
    assert.equal(data.user_id, 'message-sender');
    assert.equal('socket' in data, false);
});

test('unauthenticated requests cannot use a supplied data user ID for $user_id rules', async t => {
    t.mock.method(crud, 'send', async request => ({
        object: [authorizationDocument(request.filter.query.$or[1]?.key || 'api-key')]
    }));

    const result = await check({
        method: 'object.read',
        organization_id: 'org',
        apikey: 'api-key',
        storage: 'forged-user',
        user_id: 'forged-user'
    });

    assert.equal(result, false);
});
