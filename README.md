# keycloak-jwt-validator-middleware

## How to use this middleware

```
import { keycloakJwtValidatorMiddleware } from "@faissalbl/keycloak-jwt-validator-middleware";

app.use(
  keycloakAuth({
    issuer: process.env.KC_ISSUER,
    audience: process.env.KC_AUDIENCE,
    jwksUri: process.env.KC_JWKS_URI,
  })
);
```
