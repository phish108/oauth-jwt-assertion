"use strict";

const debug = require("debug")("jwt-assertion:handlers:authorize");

/**
 * This module is part of the jwt-bearer assertion handling.
 *
 * This module handles the authorization of one client for another client.
 *
 */
module.exports = function authzFactory(provider, settings) { // eslint-disable-line
    return async function authorize(jwt, ctx) {

        const azp = jwt.payload.azp;
        const claims = ctx.oidc.assertion_grant.payload;

        if (ctx.oidc.client.clientId !== jwt.payload.iss &&
          typeof azp === "string") {

            debug("authorize subject access");
            if (!ctx.oidc.assertion_grant.sub) {
                const user = await settings.accountById(claims.sub);

                if (!user) {
                    debug("requested subject not found");
                    throw "invalid assertion request";
                }

                ctx.oidc.assertion_grant.sub = user;
            }

            if (!azp.length) {
                debug("authorized party must not be empty");
                throw "invalid assertion request";
            }

            if (Array.isArray(ctx.oidc.client.redirectUris)) {
                if(ctx.oidc.client.redirectUris.indexOf(azp) < 0)  {
                    debug("authorizing client does not match the authorized party");
                    throw "invalid assertion request";
                }
            }
            else if (ctx.oidc.client.redirectUris !== azp) {
                debug("authorizing client single does not match the authorized party");
                throw "invalid assertion request";
            }

            // the sub must be the same as the original sub, to indicate
            // the users consent

            debug("check subject client %O",ctx.oidc.assertion_grant.client.contacts);
            debug("if it matches %O",jwt.payload.sub);
            if (Array.isArray(ctx.oidc.assertion_grant.client.contacts) &&
                ctx.oidc.assertion_grant.client.contacts.indexOf(jwt.payload.sub) >= 0) {
                debug("the assertion client is not registered to the sub provided ");
                throw "invalid assertion request";
            }
        }
    };
};
