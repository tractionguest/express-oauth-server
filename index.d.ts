// Type definitions for @node-oauth/express-oauth-server 3.0.0
// Project: https://github.com/node-oauth/express-oauth-server
// Definitions by: Arne Schubert <https://github.com/atd-schubert>
// Definitions: https://github.com/DefinitelyTyped/DefinitelyTyped
// TypeScript Version: 2.3

import * as express from "express";
import * as OAuth2Server from "@node-oauth/oauth2-server";

declare namespace ExpressOAuthServer {
  interface Options extends OAuth2Server.ServerOptions {
    useErrorHandler?: boolean | undefined;
  }
}

declare class ExpressOAuthServer {
  server: OAuth2Server;

  constructor(options: ExpressOAuthServer.Options);

  authenticate(
    options?: OAuth2Server.AuthenticateOptions
  ): (
    request: express.Request,
    response: express.Response,
    next: express.NextFunction
  ) => Promise<OAuth2Server.Token>;

  authorize(
    options?: OAuth2Server.AuthorizeOptions & {
      continueMiddleware?: boolean | undefined;
    }
  ): (
    request: express.Request,
    response: express.Response,
    next: express.NextFunction
  ) => Promise<OAuth2Server.AuthorizationCode>;

  token(
    options?: OAuth2Server.TokenOptions & {
      continueMiddleware?: boolean | undefined;
    }
  ): (
    request: express.Request,
    response: express.Response,
    next: express.NextFunction
  ) => Promise<OAuth2Server.Token>;
}

export = ExpressOAuthServer;
