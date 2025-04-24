# Implementing OAuth for Streamable HTTP Server & Client without PKCE

## Overview

This repo provides:
1. A Streamable HTTP Server with with support OAuth (via device flow) 
2. A Streamable HTTP Client with support for OAuth (in headless mode)


## OAuth Support

At the time of writing this, I wasn't able to use the [MCP Inspector](https://modelcontextprotocol.io/docs/tools/inspector) to test a Streamable HTTP Server with OAuth. This set me down the path of implementing OAuth through device flow. 

In a typical browser-based flow (say using the MCP Inspector):
1. MCP Client requests connection to MCP server.
2. Server authorizes clients through a GitHub AuthProvider (redirect to GitHub); once user authorizes the scope, Server's callback handler:
     a. Retrieves access token from GitHub, then retrieves user data
     b. Stores access token + new session token in its token store
     c. Generates temp auth code for client, saves it with newly generated session token
     d. Redirects back to client with temp auth code
3. Client exchanges temp auth code for session token, uses for subsequent requests

I wanted to replace this browser flow based OAuth flow with device flow based OAuth. This would work as follows:

<img width="610" alt="image" src="https://github.com/user-attachments/assets/fb5bbda1-2f10-475c-b82a-7e8e16e64bc1" />

In device flow based OAuth, we don't need PKCE because:
1. There's no redirect or client-side code handling.
2. The device code flow is inherently more secure because:
	- User opens the URL and enters code on GitHub's page directly
	- All token exchange happens server-to-server
	- The device code itself is short-lived and can only be used by the same client that requested it (our server)
	- Only the user code is passed down from the server to the client

However, we also don't have the browser for session storage. We may still need to implement certain methods of that the MCP's OAuthServerProvider currently requires (e.g. exchangeAuthorizationCode and challengeForAuthorizationCode).

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

