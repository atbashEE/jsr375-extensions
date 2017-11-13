# jsr375-extensions
Extensions for JSR 375 (Java EE Security API) like custom handling for JWT and OAuth2 tokens 


## code/jwt

Contains an extension which consumes JWT tokens which can be used for securing a JAX-RS endpoint.

The processing of the JWT payload, from the header, is up to the developer and thus the MicroProfile [JWT Auth specification](https://wiki.eclipse.org/MicroProfile/JWT_Auth) JSON claims could be used. This is done in the example.

For more info, have a look at the [readme](https://github.com/atbashEE/jsr375-extensions/blob/master/examples/jwt/README.md).
  
## code/oauth2

Contains an extension using the OAuth2 Authorization code flow to authenticate the user within a Web application.

For more info, have a look at the [readme](https://github.com/atbashEE/jsr375-extensions/blob/master/examples/oauth2/README.md).