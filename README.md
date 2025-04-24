# Implementing OAuth for Streamable HTTP Server & Client without PKCE

## Overview

This repo provides:
1. Streamable HTTP Server with OAuth 
2. Streamable Client with OAuth


## Server-to-Server OAuth 

At the time of writing this, I wasn't able to find a way to use the [MCP Inspector](https://modelcontextprotocol.io/docs/tools/inspector) to test a Streamable HTTP Server with OAuth. 

In a typical browser-based flow (say using the MCP Inspector), my understanding is that:
1. MCP Client requests connection to MCP server.
2. Server authorizes clients through GHAuthProvider (redirect to GitHub); once user authorizes the scope, Server's callback handler:
     a. Retrieves access token from GitHub, then retrieves user data
     b. Stores access token + new session token in its token store
     c. Generates temp auth code for client, saves it with new session token
     d. Redirects back to client with temp auth code
3. Client exchanges temp auth code for session token, uses for subsequent requests
4. On reconnection, Server validates session via verifyAccessToken method

I wanted to replace browser flow with device flow based OAuth. This would work as follows:

Client                          Server                          GitHub
     |                               |                               |
     |-- authorizeHeadless() ------->|                               |
     |                               |-- device code request -------->|
     |                               |<-- device code & user code ----|
     |<-- device code & user code ---|                               |
     |                               |                               |
     |   [User visits GitHub and enters code manually]              |
     |                               |                               |
     |-- pollForAuthorization() ---->|                               |
     |                               |-- check auth status --------->|
     |                               |<-- access token --------------|
     |<-- MCP session token ---------|                               |


In device flow, we don't need PKCE because:
1. There's no redirect or client-side code handling.
2. The device code flow is inherently more secure because:
	- User enters code on GitHub's site directly
	- All token exchange happens server-to-server
	- The device code itself is short-lived and can only be used by the same client that requested it (our server)
	- Only the user code is passed down from the server to the client

However, we won't have the browser for session storage and may need to store data on the local file system. And we may need to implement certain methods of that the MCP's OAuthServerProvider currently requires (e.g. exchangeAuthorizationCode and challengeForAuthorizationCode)

## How to use

1. Clone this repository. Install the dependencies.

```
npm install
```

2. Set the GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET environment variables.

3. Start the MCP Server.

```
npx tsx server/index_streamable.ts
```

4. In a different terminal, start the MCP Client. 

```
npx tsx client/client.ts
```

