const createError = require("http-errors");

function InvalidAssertion(details) {
    const response = {
        error_description: "invalid assertion request"
    };

    if (details) {
        Object.assign(response, details);
    }
    return createError(400, "invalid_request", response);
}

module.exports = {
    InvalidAssertion
};
