# README #

<Under development>

SAML2.0 implementation in OpenSAML Java library.

More on OpenSAML: https://wiki.shibboleth.net/confluence/display/OpenSAML/Home


### What is this repository for? ###

This repo contains implementation of Service Provider (SP) entity, where it protects the resource for which SAML authentication at Identity Provider (IdP) required to access the resource.

Following SAML Bindings and their combinations supports:
 - Request Bindings:  HTTP-Redirect and HTTP-POST
 - Response Bindings: Artifact and HTTP-POST

Following NameID format supports:
 - Unspecified 
 - Email address

### How do I get set up? ###

* Summary of set up

This repo tested with Shibboleth IdP 2.4.0

* Configuration
* Dependencies
* Database configuration
* How to run tests

Check metadata by accessing http://<hostname>:8080/saml/trust/metadata.

* Deployment instructions

### Contribution guidelines ###

* Writing tests
* Code review
* Other guidelines

### Who do I talk to? ###

* Repo owner or admin
* Other community or team contact

