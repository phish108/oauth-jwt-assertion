"use strict";

const debug = require("debug")("jwt-assertion:validate-payload");
const { InvalidRequestError } = require("oidc-provider/lib/helpers/errors");
const JWT = require("oidc-provider/lib/helpers/jwt");
const { JWK: { asKeyStore } } = require("node-jose");

module.exports = function factory(provider, settings) { // eslint-disable-line
    return async function verifyAssertionPayload(ctx, next) {
        debug("verify assertion payload");

        // verify the cnf key
        const cnf =  ctx.oidc.assertion_grant.body.cnf;

        // If the cnf claim contains a key references
        if (typeof cnf === "object" && cnf.hasOwnProperty("kid")) {
            // The kid MUST match the iss-sub tuple.
            // => find the cnf kid in the key store
            const cnfKey = await settings.adapter("ConfirmationKeys").find(cnf.kid);

            if (!cnfKey) {
                debug("invalid cnf claim");
                ctx.throw(new InvalidRequestError("invalid cnf claim"));
            }
            // => verify the iss and sub
            if (cnfKey.iss !== assIssuer ||
                cnfKey.sub !== ctx.oidc.assertion_grant.body.sub) {
                debug("cnf claim mismatch");
                ctx.throw(new InvalidRequestError("mismatching cnf claim"));
            }

            // the assertion MUST be signed with the kid
            const jwks = await asKeyStore(cnfKey.jwks);

            try {
            // TODO verify audience (despite the package being encrypted
            // for us)
                const isverified = await JWT.verify(jwt, jwks);

                if (!isverified) {
                // debug("not verified");
                    throw "not verified";
                }
            }
            catch (err) {
                debug("cnf verification error");
                debug(err);
                ctx.throw(new InvalidRequestError("assertion cnf mismatch"));
            }
        }
        else {
            // all assertions without cnf-key references must be signed by
            // the client.

        // IMPORTANT: need to process the client's keystore before handing
        // it to the verify()-method

        // if the JWT is presented in JSON serialisation, then the JWS MUST be signed with the client keys
            client.jwks = await asKeyStore(client.jwks);

            try {
            // TODO verify audience (despite the package being encrypted
            // for us)
                const isverified = await JWT.verify(jwt, client.jwks);

                if (!isverified) {
                // debug("not verified");
                    throw "not verified";
                }
            }
            catch (err) {
                debug("iss verification error");
                debug(err);
                ctx.throw(new InvalidRequestError("assertion issuer mismatch"));
            }
        }

        ctx.oidc.assertion_grant.client = client;

        await next();
    };
};
