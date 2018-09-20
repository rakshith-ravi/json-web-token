'use strict'

var read = require('fs').readFileSync
var test = require('tape')
var b64url = require('base64-url')

var jwt = require('../.')

var payload = {
	iss: 'my_issurer',
	aud: 'World',
	iat: 1400062400223,
	typ: '/online/transactionstatus/v2',
	request: {
		myTransactionId: '[myTransactionId]',
		merchantTransactionId: '[merchantTransactionId]',
		status: 'SUCCESS'
	}
}

var secret = 'TOPSECRETTTTT'
var theToken = null
var theTokenSign = null
var theTokenSignWithHeaders = null
var algorithms

test('get the error class', function (assert) {
	var JWTError = jwt.JWTError
	assert.equal(typeof JWTError, 'function')
	assert.ok((new JWTError()) instanceof Error)
	assert.end()
})

test('get the jwt supported algorithms', function (assert) {
	algorithms = jwt.getAlgorithms()
	assert.deepEqual(typeof algorithms, 'object')
	assert.ok(Object.keys(algorithms).length)
	assert.end()
})

test('jwt - encode with callback / hmac', function (assert) {
	jwt.encode(secret, payload, function (err, token) {
		assert.deepEqual(err, null)
		assert.ok(token)
		assert.deepEqual(token.split('.').length, 3)
		theToken = token
		assert.end()
	})
})

test('jwt - encode with callback / sign', function (assert) {
	var pem = read(__dirname + '/fixtures/test.pem').toString('ascii')
	jwt.encode(pem, payload, 'RS256', function (err, token) {
		assert.deepEqual(err, null)
		assert.ok(token)
		theTokenSign = token
		assert.deepEqual(token.split('.').length, 3)
		assert.end()
	})
})

test('jwt - encode with callback / bad algorithm', function (assert) {
	jwt.encode(secret, payload, 'wow', function (err) {
		assert.deepEqual(err.message, 'The algorithm is not supported!')
		assert.end()
	})
})

test('jwt - decode with callback / hmac', function (assert) {
	jwt.decode(secret, theToken, function (err, result) {
		assert.deepEqual(err, null)
		assert.deepEqual(result.payload, payload)
		assert.end()
	})
})

test('jwt - decode with callback / sign', function (assert) {
	var crt = read(__dirname + '/fixtures/test.crt').toString('ascii')
	jwt.decode(crt, theTokenSign, function (err, result) {
		assert.deepEqual(err, null)
		assert.deepEqual(result.payload, payload)
		assert.end()
	})
})

test('jwt + custom headers - encode with callback / sign', function (assert) {
	var pem = read(__dirname + '/fixtures/test.pem').toString('ascii')
	var payloadAndHeaders = {
		payload: payload,
		header: {
			kid: 'TestKeyId'
		}
	}

	jwt.encode(pem, payloadAndHeaders, 'RS256', function (err, token) {
		assert.deepEqual(err, null)
		assert.ok(token)
		theTokenSignWithHeaders = token
		assert.deepEqual(token.split('.').length, 3)
		assert.end()
	})
})

test('jwt + custom headers - decode with callback / sign', function (assert) {
	var crt = read(__dirname + '/fixtures/test.crt').toString('ascii')
	jwt.decode(crt, theTokenSignWithHeaders, function (err, result) {
		assert.deepEqual(err, null)
		assert.deepEqual(result.payload, payload)
		assert.deepEqual(result.header.kid, 'TestKeyId')
		assert.end()
	})
})

test('jwt - decode with callback / bad algorithm', function (assert) {
	var t = theToken.split('.').slice(1, 3)
	var badHeader = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJ3b3cifQ'
	t = badHeader + '.' + t.join('.')
	jwt.decode(secret, t, function (err) {
		assert.equal(err.name, 'JWTError')
		assert.equal(err.message, 'The algorithm is not supported!')
		assert.end()
	})
})

test('jwt - decode with callback / bad token', function (assert) {
	var badToken = theToken.split('.')
	badToken[1] = 'bad token hash'
	jwt.decode(secret, badToken.join('.'), function (err) {
		assert.equal(err.name, 'JWTError')
		assert.equal(err.message, 'Invalid key!')
		assert.end()
	})
})

test('jwt - decode with callback / invalid key', function (assert) {
	jwt.decode('wow', theToken, function (err) {
		assert.equal(err.name, 'JWTError')
		assert.equal(err.message, 'Invalid key!')
		assert.end()
	})
})

test('jwt - encode with callback / null payload', function (assert) {
	jwt.encode(secret, null, function (err) {
		assert.equal(err.name, 'JWTError')
		assert.equal(err.message, 'The key and payload are mandatory!')
		assert.end()
	})
})

test('jwt - encode with callback / empty payload', function (assert) {
	jwt.encode(secret, {}, function (err) {
		assert.equal(err.name, 'JWTError')
		assert.equal(err.message, 'The payload is an empty object!')
		assert.end()
	})
})

test('jwt - encode with callback / null secret', function (assert) {
	jwt.encode(null, payload, function (err) {
		assert.equal(err.name, 'JWTError')
		assert.equal(err.message, 'The key and payload are mandatory!')
		assert.end()
	})
})

test('jwt - decode with callback / null key', function (assert) {
	jwt.decode(null, theToken, function (err) {
		assert.equal(err.name, 'JWTError')
		assert.equal(err.message, 'The key and token are mandatory!')
		assert.end()
	})
})

test('jwt - decode with callback / bad token', function (assert) {
	jwt.decode(secret, theToken.split('.').slice(0, 2).join('.'), (err) => {
		assert.equal(err.name, 'JWTError')
		assert.equal(err.message, 'The JWT should consist of three parts!')
		assert.end()
	})
})

//
// test the jwt vulnerability because of the "none" algorithm
// this alg is intended to be used for situations where the integrity
// of the token has already been verified
//

test('should not encode for the "none" algorithm', function (assert) {
	jwt.encode(secret, payload, 'none', function (err) {
		assert.equal(err.name, 'JWTError')
		assert.equal(err.message, 'The algorithm is not supported!')
		assert.end()
	})
})

test('should not decode for the "none" algorithm', function (assert) {
	jwt.encode(secret, payload, (err, token) => {
		var badToken = token.split('.')
		var badAlg = b64url.encode(JSON.stringify({ typ: 'JWT', alg: 'none' }))
		badToken[0] = badAlg
		jwt.decode(secret, badToken.join('.'), (err) => {
			assert.deepEqual(!!err, true)
			assert.equal(err.name, 'JWTError')
			assert.equal(err.message, 'The algorithm is not supported!')
			assert.end()
		})
	})
})
