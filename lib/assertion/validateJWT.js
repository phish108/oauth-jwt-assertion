"use strict";

const debug = require("debug")("jwt-assertion:assertion:validateJWT");
const { InvalidRequestError } = require("oidc-provider/lib/helpers/errors");
const jose = require("node-jose");


module.exports = function factory(provider) {
    return async function validateJWT(ctx, next) {

        debug("validate JWT with a Key");
        const origJwt = ctx.oidc.assertion_grant.jwt;
        const payload = ctx.oidc.assertion_grant.payload;

        // find issuer as client
        debug(`find client via issuer: ${payload.iss} %O`, payload);

        const client = await provider.Client.find(payload.iss);

        if (!client) {
            debug("client not found");
            ctx.throw(new InvalidRequestError("invalid assertion client"));
        }

        debug("client object: %O", client);

        if (!client.jwks) {
            debug("client has no key set");
            ctx.throw(new InvalidRequestError("bad assertion client"));
        }

        if (!(client.jwks.keys && client.jwks.keys.length)) {
            debug("client has no keys");
            ctx.throw(new InvalidRequestError("bad assertion client"));
        }

        try {
            debug("validate keystore");
            const keyStore = await jose.JWK.asKeyStore(client.jwks.keys);

            debug("validate jwt");
            const isValid = await jose.JWS.createVerify(keyStore)
                .verify(origJwt);
            // const isValid = await origJwt.perform(keyStore);

            if (!isValid) {
                throw new Error("not validated");
            }
        }
        catch (err) {
            debug("invalid assertion signature %O", err);
            ctx.throw(new InvalidRequestError("invalid assertion"));
        }

        ctx.oidc.assertion_grant.client = client;

        await next();
    };
};
