"use strict";

const debug = require("debug")("jwt-assertion:pipeline");
const compose = require("koa-compose");
const stack = require("./assertion");
const handler = require("./handlers");
const { InvalidRequestError } = require("oidc-provider/lib/helpers/errors");

const grantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const grantTypeParam = ["assertion"];

const handlerRegistry = [];

async function validateAssertionHandlers(ctx, next) {
  const payload = ctx.oidc.assertion_grant.payload;

  try {
    for (var i = 0; i < handlerRegistry.length; i++) {
        await handlerRegistry[i](payload, ctx);
    }
  }
  catch (error) {
    ctx.throw(new InvalidRequestError("invalid assertion provided"));
  }

  await next();
}

// we should have a factory for the settings, too.
function settingsfactory(provider, settings) {
    debug("prepare pipeline");

    // init the default handler
    // NOTE THAT NO HANDLER SHOULD ASSUME THE EXISTANCE OF OTHER HANDLERS
    registerHandler(handler.authorize(provider, settings));
    registerHandler(handler.authenticate(provider, settings));

    return function jwtAssertionGrantTypeFactory(prv) {
        debug("init pipeline");
        return compose([
            stack.parameterCheck,
            stack.scopeValidation,
            stack.decryptAssertion(provider),
            stack.verifyJWT,
            stack.validateJWT(provider);
            stack.loadSub(provider, settings),
            validateAssertionHandlers,
            stack.grantAccessToken(provider),
            stack.debugAssertionContext
        ]);
    };
};

/**
 * self register the assertion grant type to the provider.
 * @param provider - the provider instance
 * @param settings - the settings instance (needed for account handling)
 *
 * This function hides the grant type registration from the business logic.
 */
function registerGrantType(provider, settings) {
  provider.registerGrantType(grantType,
                             settingsfactory(provider, settings),
                             grantTypeParam));
}

/**
 * registers a new handler to the grant type handler
 * @param handler - the handler function
 *
 * a handler is responsible for handling one validation of the assertion payload.
 * A handler has the following signature:
 *
 * ```
 * async function (payload, ctxt);
 * ```
 *
 * Handlers MUST NOT fail if they are don't meet their conditions.
 *
 * Handlers MUST throw errors if they meet their conditions
 * but cannot verify them.
 */
function registerHandler(handler) {
    if (handler &&
        typeof handler === "function" &&
        handlerRegistry.indexOf(handler) <= 0) {
      handlerRegistry.push(handler);
    }
}

module.exports = {
  registerHandler,
  registerGrantType
};
