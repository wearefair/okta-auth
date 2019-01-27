/*
A package for authenticating as an end user with Okta, with support for MFA.

Construct a client with your Okta domain, and a struct that implements the Prompts interface.

After calling `Authenticate`, if a second factor is required the appropriate methods from the
Prompts interface will be called to guide the user through the authentication flow.
*/
package okta
