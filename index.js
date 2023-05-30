/**
 * Module dependencies.
 */
const NodeOAuthServer = require('@node-oauth/oauth2-server');
const { Request, Response } = require('@node-oauth/oauth2-server');
const InvalidArgumentError = require('@node-oauth/oauth2-server/lib/errors/invalid-argument-error');
const UnauthorizedRequestError = require('@node-oauth/oauth2-server/lib/errors/unauthorized-request-error');

class ExpressOAuthServer {
  constructor(options) {
    this.options = options || {};

    if (!this.options.model) {
      throw new InvalidArgumentError('Missing parameter: `model`');
    }
    this.useErrorHandler = this.options.useErrorHandler === true;
    this.continueMiddleware = this.options.continueMiddleware === true;

    delete this.options.useErrorHandler;
    delete this.options.continueMiddleware;

    this.server = new NodeOAuthServer(this.options);
  }

  /**
   * Authentication Middleware.
   *
   * Returns a middleware that will validate a token.
   *
   * (See: https://tools.ietf.org/html/rfc6749#section-7)
   */
  authenticate(options) {
    return async (req, res, next) => {
      const request = new Request(req);
      const response = new Response(res);
      let token;
      try {
        token = await this.server.authenticate(request, response, options);
      } catch (err) {
        this._handleError(res, null, err, next);
        return;
      }
      res.locals.oauth = { token };
      return next();
    }
  }

  /**
   * Authorization Middleware.
   *
   * Returns a middleware that will authorize a client to request tokens.
   *
   * (See: https://tools.ietf.org/html/rfc6749#section-3.1)
   */
  authorize(options) {
    return async (req, res, next) => {
      const request = new Request(req);
      const response = new Response(res);
      let code;
      try {
        code = await this.server.authorize(request, response, options);
      } catch (err) {
        this._handleError(res, response, err, next);
        return;
      }
      res.locals.oauth = { code };
      if (this.continueMiddleware) {
        next();
      }
      return this._handleResponse(req, res, response);
    }
  }


  /**
   * Authorization Middleware.
   *
   * Returns a middleware that will authorize a client to request tokens.
   *
   * (See: https://tools.ietf.org/html/rfc6749#section-3.1)
   */
  token(options) {
    return async (req, res, next) => {
      const request = new Request(req);
      const response = new Response(res);
      let token;
      try {
        token = await this.server.token(request, response, options);
      } catch (err) {
        this._handleError(res, response, err, next);
        return;
      }
      res.locals.oauth = { token };
      if (this.continueMiddleware) {
        next();
      }
      return this._handleResponse(req, res, response);
    }
  }

  /**
   * Grant Middleware.
   *
   * Returns middleware that will grant tokens to valid requests.
   *
   * (See: https://tools.ietf.org/html/rfc6749#section-3.2)
   */
  _handleResponse(req, res, oauthResponse) {
    if (oauthResponse.status === 302) {
      const location = oauthResponse.headers.location;
      delete oauthResponse.headers.location;
      res.set(oauthResponse.headers);
      res.redirect(location);
      return;
    }
    res.set(oauthResponse.headers);
    res.status(oauthResponse.status).send(oauthResponse.body);
  }

  /**
   * Handles errors depending on the options of `this.useErrorHandler`.
   * Either calls `next()` with the error (so the application can handle it), or returns immediately a response with the error.
   */
  _handleError(res, oauthResponse, error, next) {
    if (this.useErrorHandler) {
      return next(error);
    }

    if (oauthResponse) {
      res.set(oauthResponse.headers);
    }

    res.status(error.code);

    if (error instanceof UnauthorizedRequestError) {
      return res.send();
    }

    return res.send({ error: error.name, error_description: error.message });
  }
}


module.exports = ExpressOAuthServer;
