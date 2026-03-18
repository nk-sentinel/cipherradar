const jwt = require('jsonwebtoken');

const secret = 'my-secret-key';

// GOOD: HS256 (but secret is hardcoded — Pass 2 will catch this)
const token = jwt.sign({ user: 'admin' }, secret, { algorithm: 'HS256' });

// BAD: alg:none
const unsafeToken = jwt.sign({ user: 'admin' }, '', { algorithm: 'none' });

// Verify with specific algorithms
jwt.verify(token, secret, { algorithms: ['HS256', 'HS384'] });
