const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

module.exports.keycloakJwtValidatorMiddleware = function (options) {
    if (!options || !options.jwksUri || !options.audience || !options.issuer) {
        throw new Error('Missing required options: jwksUri, audience, issuer');
    }

    const client = jwksClient({
        jwksUri: options.jwksUri,
        cache: true,
        rateLimit: true
    });

    function getKey(header, callback) {
        client.getSigningKey(header.kid, function(err, key) {
            if (err) {
                return callback(err);
            }
            callback(null, key.getPublicKey());
        });
    }

    return function (req, res, next) {
        const auth = req.headers.authorization;
        if (!auth || !auth.startsWith('Bearer ')) {
            return res.status(401).send('Unauthorized: No token provided');
        }
        
        const token = auth.split(' ')[1];

        jwt.verify(
            token,
            getKey,
            {
                audience: options.audience,
                issuer: options.issuer,
                algorithms: ['RS256']
            },
            (err, decoded) => {
                if (err) {
                    return res.status(401).send('Unauthorized: ' + err.message);
                }
                req.user = decoded;
                next();
            }
        );
    }
}