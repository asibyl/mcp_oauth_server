import { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import { AuthorizationParams, OAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { OAuthClientInformationFull, OAuthTokens, OAuthTokenRevocationRequest } from "@modelcontextprotocol/sdk/shared/auth.js";
import { Response } from "express";
import fs from 'fs/promises';
import path from 'path';
import dotenv from 'dotenv';    
import * as crypto from 'crypto';
import { tokenStore } from './TokenStore.js';
import { SessionData } from './SessionData.js';
import { ClientWithVerifier } from './ClientWithVerifier.js';
import { existsSync, mkdirSync } from 'fs';

const currentDir = path.dirname(new URL(import.meta.url).pathname);
const DEFAULT_CLIENTS_FILE = path.join(currentDir, '.auth/registered_clients.json');

export class GitHubServerAuthProvider implements OAuthServerProvider {
    private _clientsMap: Map<string, OAuthClientInformationFull> = new Map();
    private _clientsStoreImpl: OAuthRegisteredClientsStore;
    private _clientsFilePath: string;
    private _sessionStore: Map<string, SessionData> = new Map();
    private _tempAuthCodes: Map<string, { sessionToken: string, expires: number }> = new Map();
    private _deviceCodes = new Map<string, {
        clientId: string;
        githubDeviceCode: string;
        userCode: string;
        verificationUri: string;
        expiresAt: number;
        interval: number;
        sessionToken?: string;
    }>();

    constructor() {
        dotenv.config();

        // Check if the environment variables are set
        const requiredEnvVars = ['GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET'];
        const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);
        if (missingEnvVars.length > 0) {
            throw new Error(`Missing required environment variables: ${missingEnvVars.join(', ')}`);
        }

        this._clientsFilePath = path.resolve(process.cwd(), DEFAULT_CLIENTS_FILE);

        // Ensure .auth directory exists
        const authDir = path.dirname(this._clientsFilePath);
        if (!existsSync(authDir)) {
            mkdirSync(authDir, { recursive: true });
        }

        this._clientsStoreImpl = {
            getClient: (clientId: string) => {
                return this._clientsMap.get(clientId);
            },

            registerClient: (client: OAuthClientInformationFull) => {
                this._clientsMap.set(client.client_id, client);
 
                this._saveClientsToFile().catch(err => {
                    console.error("Failed to save client registration:", err);
                });
                return client;
            }
        };

        this._loadClientsFromFile().catch(err => {
            console.error("Failed to load registered clients:", err);
        });

        setInterval(() => {
            tokenStore.cleanExpiredTokens();
        }, 60000);
    }

    private async _storeSessionData(state: string, data: SessionData): Promise<void> {
        if (!state) {
            throw new Error("Cannot store session data: state parameter is missing");
        }

        this._sessionStore.set(state, data);
        console.log(`Session data stored for state: ${state}`);
    }

    private _getSessionData(state: string): SessionData | undefined {
        return this._sessionStore.get(state);
    }

    private _clearSessionData(state: string): void {
        this._sessionStore.delete(state);
        console.log(`Session data cleared for state: ${state}`);
    }

    private async _loadClientsFromFile(): Promise<void> {
        try {
            await fs.access(this._clientsFilePath)
                .catch(() => {
                    console.log("No saved clients file found. Starting with empty clients list.");
                    return Promise.reject(new Error("File not found"));
                });

            const fileContent = await fs.readFile(this._clientsFilePath, { encoding: 'utf8' });
            const clientsData = JSON.parse(fileContent);

            this._clientsMap.clear();
            for (const [clientId, clientData] of Object.entries(clientsData)) {
                this._clientsMap.set(clientId, clientData as OAuthClientInformationFull);
            }

            console.log(`Loaded ${this._clientsMap.size} registered clients from file.`);
        } catch (err) {
            if ((err as Error).message !== "File not found") {
                console.error("Error loading clients from file:", err);
            }
        }
    }

    private async _saveClientsToFile(): Promise<void> {
        try {
            const clientsObject: Record<string, OAuthClientInformationFull> = {};
            for (const [clientId, clientData] of this._clientsMap.entries()) {
                clientsObject[clientId] = clientData;
            }

            await fs.writeFile(
                this._clientsFilePath,
                JSON.stringify(clientsObject, null, 2),
                { encoding: 'utf8' }
            );

            console.log(`Saved ${this._clientsMap.size} registered clients to file.`);
        } catch (err) {
            console.error("Error saving clients to file:", err);
            throw err;
        }
    }

    get clientsStore(): OAuthRegisteredClientsStore {
        return this._clientsStoreImpl;
    }

    // required method for OAuthServerProvider
    async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
        console.log(`Authorizing client ${client.client_id} using device flow`);
        try {
            const deviceAuthData = await this.initiateDeviceFlow(client.client_id);
            res.json(deviceAuthData);
        } catch (error) {
            console.error("Device flow error:", error);
            res.status(500).json({ 
                error: "server_error", 
                error_description: `Failed to initialize device flow: ${error}`
            });
        }
    }

    // required method for OAuthServerProvider 
    // (not needed in device flow
    // in browser flow, the challenge is needed to verify against code verifier to ensure the same client that started the flow is completing it
    async challengeForAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
        try {
            console.log("Challenging for authorization code ", authorizationCode);
            const tempCodeData = this._tempAuthCodes.get(authorizationCode);
            if (!tempCodeData || tempCodeData.expires < Date.now()) {
                this._tempAuthCodes.delete(authorizationCode);
                throw new Error("Invalid or expired authorization code");
            }

            const sessionToken = tempCodeData.sessionToken;
            const storedToken = tokenStore.getToken(sessionToken);

            if (!storedToken) {
                throw new Error("Invalid session token");
            }

            return storedToken.clientCodeChallenge || '';
        } catch (error) {
            console.error("Error retrieving code challenge:", error);
            throw new Error(`Failed to get code challenge: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    // required method for OAuthServerProvider
    async exchangeRefreshToken(client: OAuthClientInformationFull, refreshToken: string, scopes?: string[]): Promise<OAuthTokens> {
        throw new Error("Refresh token exchange not implemented");
    }

    // required method for OAuthServerProvider
    async verifyAccessToken(token: string): Promise<AuthInfo> {
        const storedToken = tokenStore.getToken(token);

        if (!storedToken) {
            throw new Error("Invalid or expired token");
        }

        if (storedToken.expiresAt < Date.now()) {
            tokenStore.removeToken(token);
            throw new Error("Token has expired");
        }

        return {
            token: token,
            clientId: storedToken.clientId,
            scopes: storedToken.scopes,
            expiresAt: storedToken.expiresAt
        };
    }

    // required method for OAuthServerProvider 
    async revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
        throw new Error("Token revocation not implemented");
    }

    // required method for OAuthServerProvider
    // not needed in device flow, where device code replaces auth code
    async exchangeAuthorizationCode(client: ClientWithVerifier, authorizationCode: string): Promise<OAuthTokens> {
        try {
            console.log(`Exchanging authorization code for client ${client.client_id}`);
            console.log("Using Authorization code ", authorizationCode);

            const tempCodeData = this._tempAuthCodes.get(authorizationCode);
            if (!tempCodeData || tempCodeData.expires < Date.now()) {
                this._tempAuthCodes.delete(authorizationCode);
                throw new Error("Invalid or expired authorization code");
            }

            this._tempAuthCodes.delete(authorizationCode);

            const sessionToken = tempCodeData.sessionToken;
            const storedToken = tokenStore.getToken(sessionToken);

            if (!storedToken) {
                throw new Error("Invalid session token");
            }

            return {
                access_token: sessionToken,
                token_type: "Bearer",
                expires_in: Math.floor((storedToken.expiresAt - Date.now()) / 1000),
                refresh_token: crypto.randomBytes(32).toString('hex'),
                scope: storedToken.scopes.join(' ')
            };
        } catch (error) {
            console.error("Error exchanging authorization code for tokens:", error);
            throw new Error(`Failed to exchange authorization code: ${error instanceof Error ? error.message : String(error)}`);
        }
    }


    async initiateDeviceFlow(clientId: string): Promise<{
        device_code: string;
        user_code: string;
        verification_uri: string;
        verification_uri_complete: string;
        expires_in: number;
        interval: number;
    }> {
        console.log(`Initiating GitHub device flow for client with id: ${clientId}`);
        // Request device code from GitHub
        const response = await fetch('https://github.com/login/device/code', {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                client_id: process.env.GITHUB_CLIENT_ID,
                scope: 'read:user user:email'
            })
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error('GitHub error response:', {
                status: response.status,
                statusText: response.statusText,
                body: errorText
            });
            throw new Error(`GitHub device code request failed: ${response.status} ${response.statusText}\n${errorText}`);
        }
        
        // Parse GitHub response
        const data = await response.json();
        const {
            device_code,
            user_code,
            verification_uri,
            expires_in,
            interval
        } = data;
        
        // Generate internal device code to track this request
        const internalDeviceCode = crypto.randomBytes(32).toString('hex');
        
        // Store the codes
        this._deviceCodes.set(internalDeviceCode, {
            clientId,
            githubDeviceCode: device_code,
            userCode: user_code,
            verificationUri: verification_uri,
            expiresAt: Date.now() + (expires_in * 1000),
            interval
        });
        
        // Return details to client
        return {
            device_code: internalDeviceCode, // Return our internal code, not GitHub's
            user_code,
            verification_uri,
            verification_uri_complete: `${verification_uri}?user_code=${user_code}`,
            expires_in,
            interval
        };
    }

    // Method to check authorization status
    async checkDeviceCodeStatus(deviceCode: string): Promise<OAuthTokens | { error: string, error_description: string }> {
        // Get device code data
        const deviceData = this._deviceCodes.get(deviceCode);
        if (!deviceData) {
            return { 
                error: 'invalid_grant', 
                error_description: 'Device code not found'
            };
        }
        
        // Check if expired
        if (deviceData.expiresAt < Date.now()) {
            this._deviceCodes.delete(deviceCode);
            return { 
                error: 'expired_token', 
                error_description: 'Device code has expired'
            };
        }
        
        // If we already have a session token, return it
        if (deviceData.sessionToken) {
            const storedToken = tokenStore.getToken(deviceData.sessionToken);
            if (storedToken) {
                // Clean up
                this._deviceCodes.delete(deviceCode);
                
                return {
                    access_token: deviceData.sessionToken,
                    token_type: "Bearer",
                    expires_in: Math.floor((storedToken.expiresAt - Date.now()) / 1000),
                    refresh_token: crypto.randomBytes(32).toString('hex'),
                    scope: storedToken.scopes.join(' ')
                };
            }
        }
        
        // Check with GitHub if the user has authorized
        try {
            const response = await fetch('https://github.com/login/oauth/access_token', {
                method: 'POST',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    client_id: process.env.GITHUB_CLIENT_ID,
                    client_secret: process.env.GITHUB_CLIENT_SECRET,
                    device_code: deviceData.githubDeviceCode,
                    grant_type: 'urn:ietf:params:oauth:grant-type:device_code'
                })
            });
            
            const data = await response.json();
            
            // Handle GitHub response
            if (data.error) {
                // Still pending or other error
                if (data.error === 'authorization_pending') {
                    return { 
                        error: 'authorization_pending', 
                        error_description: 'The user has not yet authorized this device'
                    };
                } else if (data.error === 'slow_down') {
                    return { 
                        error: 'slow_down', 
                        error_description: 'Polling too frequently, slow down'
                    };
                } else {
                    return { 
                        error: data.error, 
                        error_description: data.error_description || 'Error from GitHub authorization'
                    };
                }
            }
            
            // Success! User has authorized
            const { access_token } = data;
            
            // Generate MCP session token
            const sessionToken = tokenStore.storeToken(
                access_token,
                '',
                3600, // 1 hour expiration
                deviceData.clientId,
                ['read:user', 'user:email']
            );
            
            // Update device code data with session token
            this._deviceCodes.set(deviceCode, {
                ...deviceData,
                sessionToken
            });
            
            // Return tokens to client
            return {
                access_token: sessionToken,
                token_type: "Bearer",
                expires_in: 3600,
                refresh_token: crypto.randomBytes(32).toString('hex'),
                scope: "read:user user:email"
            };
        } catch (error) {
            console.error("Error checking device code status:", error);
            return { 
                error: 'server_error', 
                error_description: 'Error checking authorization status'
            };
        }
    }
}