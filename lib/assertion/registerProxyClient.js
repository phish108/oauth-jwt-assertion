// const crypto = require("crypto");

const epochTime = (date = Date.now()) => Math.floor(date / 1000);

module.exports = function factory(provider, settings) { // eslint-disable-line
    return async function registerProxyClient(ctx, next) {
        if (ctx.oidc.assertion_grant.cnf &&
          ctx.oidc.assertion_grant.body.azp &&
          ctx.oidc.assertion_grant.client &&
          ctx.oidc.assertion_grant.sub) {

          // NOTE The ProxyClient has no client secret and thus cannot connect
          //      regularly. The client contacts is limited to ONE entry, which
          //      refers to the sub authorized for this request.
          // TODO store the proxy client in the appropriate location
            const clientInfo = {
                "client_id": ctx.oidc.assertion_grant.body.azp,
                "contacts": ctx.oidc.assertion_grant.sub,
                "service_id": ctx.oidc.assertion_grant.client.clientId,
                "jwks": ctx.oidc.assertion_grant.cnf.jwks,
                "scope": ["profile", "address", "email", "phone"],
                "grantType": [
                    "urn:ietf:params:oauth:grant-type:jwt-bearer"
                ],
                client_secret_expires_at: 0,
                client_id_issued_at: epochTime(),
            };

          // user client is just like any other client, but needs to be
          // handled slightly different, so LDAP repos can be handle these
          // dynamic clients separately
            let client = settings.adapter("UserClient");

            client.addClient(clientInfo);
        }

        await next();
    };
};
