"use strict";

const debug = require("debug")("jwt-assertion:assertion:debugAssertionContext");

module.exports = async function debugAssertionContext(ctx, next) {
    debug("verify context");
    debug("%O", ctx);
    await next();
};
