"use strict";

const debug = require("debug")("jwt-assertion:handlers:authenticate");
// const JWT = require("oidc-provider/lib/helpers/jwt");

module.exports = function authnFactory(provider, settings) {
    return async function authenticate(jwt, ctx) {
        const claims = jwt.payload;

        if (claims.iss === ctx.oidc.client.clientId) {

            debug("authenticate user");
            if (claims.x_crd) {
                debug("authenticate");
                if (typeof claims.x_crd !== "string") {
                    debug("invalid x_crd claim for password authentication");
                    throw "invalid assertion provided";
                }

                const sub = claims.sub;
                const pwd = claims.x_crd;

                try {
                    const user = await settings.accountByLogin(sub, pwd);

                    if (!user) {
                        throw "no user";
                    }

                    ctx.oidc.assertion_grant.sub = user;
                    debug("user info: %O", ctx.oidc.assertion_grant.sub);
                }
                catch (error) {
                    debug("authentication failed %O", error);
                    throw "invalid assertion provided";
                }
            }

            // authentications MUST have a confirmation for later authorization
            if (  typeof jwt.payload.cnf === "object") {

                if (typeof jwt.payload.cnf !== "object") {
                    debug("assertion cnf claim is missing");
                    throw "invalid assertion provided";
                }

                // the confirmation MUST contain a (public) key object
                if(typeof jwt.payload.cnf.jwk !== "object") {
                    debug("invalid assertion cnf.jwk presented");
                    throw "invalid assertion provided";
                }

                // reject the the assertion if the JWK has no kid, because
                // the client cannot back reference to the key
                if(typeof jwt.payload.cnf.jwk.kid !== "string" && !jwt.payload.cnf.jwk.kid.length) {
                    debug("invalid assertion: cnf.jwk.kid missing");
                    throw "invalid assertion provided";
                }

                // avoid key reuse, check if the key id exists already
                // TODO: define how the key id would be findable in ldap

                // store for later client registration
                const cnf = {"keys": [claims.cnf.jwk]};
                const now = Date.now();

                // register client NOW
                debug("handle pkce session");
                if (cnf &&
                    claims.azp &&
                    ctx.oidc.assertion_grant.client &&
                    ctx.oidc.assertion_grant.sub) {

                    debug("conditions OK");
                    // NOTE The ProxyClient has no client secret and thus cannot connect
                    //      regularly. The client contacts is limited to ONE entry, which
                    //      refers to the sub authorized for this request.
                    // TODO store the proxy client in the appropriate location
                    // TODO use only the scopes that are requested
                    // TODO client_secret_expires_at should be configurable

                    // generate a random string

                    const clientInfo = {
                        "client_id": claims.azp,
                        "contacts": ctx.oidc.assertion_grant.sub.claims().sub,
                        "service_id": ctx.oidc.assertion_grant.client.clientId,
                        "jwks": cnf,
                        "scope": ["profile", "address", "email", "phone"],
                        "grantType": [
                            "urn:ietf:params:oauth:grant-type:jwt-bearer"
                        ],
                        "redirect_uris": ctx.oidc.assertion_grant.client.redirectUris,
                        "client_secret": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" // TODO generate random secret
                        // "client_secret_expires_at": 0,
                        // "client_id_issued_at": now,
                    };

                    // user client is just like any other client, but needs to be
                    // handled slightly different, so LDAP repos can be handle these
                    // dynamic clients separately
                    debug("get adapter");
                    let client = settings.adapter("ProxyClient");

                    debug("upsert %O", clientInfo);
                    await client.upsert(claims.azp, clientInfo);
                    debug("done");
                }
            }
        }
    };
};
