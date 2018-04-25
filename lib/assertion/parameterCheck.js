"use strict";

const ld = require("lodash");
const debug = require("debug")("jwt-assertion:assertion:parameterCheck");
const { InvalidRequestError } = require("oidc-provider/lib/helpers/errors");
// const instance = require("oidc-provider/lib/helpers/weak_cache");

module.exports = async function parameterCheck(ctx, next) {
    debug("parameter check");

    const { params } = ctx.oidc;
    const missing = ld.difference(["assertion", "scope"],
                                  ld.keys(ld.omitBy(params, ld.isUndefined)));

    if (!ld.isEmpty(missing)) {
        debug("scope or assertion is missing");
            // debug("%O", params);
        ctx.throw(new InvalidRequestError(`missing required parameter(s) ${missing.join(",")}`));
    }

    ctx.oidc.assertion_grant = {};

        // handle the scope correctly
    ctx.oidc.assertion_grant.scope = params.scope.split(" ");

    await next();
};
