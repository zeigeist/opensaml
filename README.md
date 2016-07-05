# README #

<Under development>

SAML2.0 implementation in OpenSAML Java library.

More on OpenSAML: https://wiki.shibboleth.net/confluence/display/OpenSAML/Home



### What is this repository for? ###

This repo contains implementation of Service Provider (SP) entity where it protects the resource for which SAML authentication required to access it.

Following SAML Bindings and their combinations supports:
 - Request Binding: Redirect and POST
 - Response Binding Artifact and POST

Following NameID format supports:
 - Unspecified 
 - Email address

Note:
1. This repo tested with Shibboleth IdP 2.4.0
2. Check metadata by accessing http://<hostname>:8080/saml/trust/metadata.


### How do I get set up? ###

* Summary of set up
* Configuration
* Dependencies
* Database configuration
* How to run tests
* Deployment instructions

### Contribution guidelines ###

* Writing tests
* Code review
* Other guidelines

### Who do I talk to? ###

* Repo owner or admin
* Other community or team contact
