"use strict";

const debug = require("debug")("jwt-assertion:debug");

module.exports = async function debugAssertionContext(ctx, next) {
        debug("verify context");
        debug("%O", ctx);
        await next();
};
