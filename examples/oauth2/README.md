# jsr375-extensions OAuth2 example 

This implements the _Authorization code_ flow of OAuth2 for Java EE Security API. 


## Alfa

The code within the extension is not production ready. There are a few major issues with is, see further on. It is the starting point ...
 
## Setup

* Add the dependency

You need to add the Maven dependency to include the code for the JWT extension for jsr375

````
    <dependency>
        <groupId>be.atbash.ee.security.jsr375</groupId>
        <artifactId>soteria-oauth2</artifactId>
        <version>0.8</version>
    </dependency>
````

* Supply OAuth2 Configuration

For OAuth2, you need to specify some configuration values like client id and client secret.
Create a CDI bean implementing **be.atbash.ee.security.soteria.oauth2.oauth2.OAuth2Configuration** which supplies these values.

Within the example, the class _GoogleConfiguration_ is responsible for this.

* Define/Configure the OAuth2 HTTP Authentication mechanism

Create a CDI bean extending **be.atbash.ee.security.soteria.oauth2.mechanism.OAuthClientServerBaseModule** and define that the Remember me option must be activated.

This is an known issue.

See the class _OAuthClientAuthenticationMechanism_ within the example code.

* Define IdentityStore(s)

Define an IdentityStore for retrieving user information from token and define groups for the user.

Since OAuth2 is actually about granting authorization to a resource, we can use it for authentication (the end user actually grant us access to his user info) but it cannot be used for authorizations within our own application.

Therefor the IdentityStore need to retrieve the information linked to the access token (by calling the user endpoint of the OAuth2 provider) and supply by some means groups.

- _DemoIdentityStore_ retrieves the user information from the Google endpoint.
- _GroupsIdentityStore_ defines hardcoded some groups.

## Issues

1. Principal isn't remembered by JASPIC, you need to specify the RememberMe option of JSR-375
2. Does not work on GlassFish 5.0 Due to the creation of the custom principal (**OAuth2User**)
3. Callback URL is hardcoded and also the root cannot be changed
4. Google is hardcoded as OAuth2 provider

