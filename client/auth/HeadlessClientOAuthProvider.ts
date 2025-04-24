import { OAuthClientProvider } from "@modelcontextprotocol/sdk/client/auth.js";
import { OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";
import * as fs from 'fs/promises';
import { existsSync, mkdirSync } from 'fs';
import * as path from 'path';

// Constants for storage keys/filenames
// Store locally in the .auth directory, no browser storage available
const SESSION_KEYS = {
    SERVER_URL: 'mcp_server_url',
    SESSION_TOKEN: 'mcp_session_token',
    CODE_VERIFIER: 'mcp_code_verifier',
    CLIENT_INFO: 'mcp_client_info',
    DEVICE_CODE: 'mcp_device_code'
};

const ENDPOINTS = {
    TOKEN: '/auth/token',
    CALLBACK: '/auth/callback',
    DEVICE_AUTHORIZE: '/auth/device/authorize',
    DEVICE_TOKEN: '/auth/device/token'
};

// Use constants to derive filenames
const getFilePath = (storageDir: string, key: string): string => {
    return path.join(storageDir, `${key}.json`);
};

export class HeadlessClientOAuthProvider implements OAuthClientProvider {
    private serverUrl: string;
    private storageDir: string;
    private _deviceCode?: string;
    
    constructor(serverUrl: string, storageDir?: string) {
        this.serverUrl = serverUrl;
        const currentDir = path.dirname(new URL(import.meta.url).pathname);
        this.storageDir = storageDir || path.join(currentDir, '.auth');
        
        // Ensure .auth directory exists
        if (!existsSync(this.storageDir)) {
            mkdirSync(this.storageDir, { recursive: true });
        }
    }
    
    get redirectUrl(): URL {
        const callbackUrl = new URL(ENDPOINTS.CALLBACK, this.serverUrl);
        return callbackUrl;
    }
    
    async clientInformation() {
        try {
            const infoFile = getFilePath(this.storageDir, SESSION_KEYS.CLIENT_INFO);
            const data = await fs.readFile(infoFile, 'utf8');
            return JSON.parse(data);
        } catch (error) {
            return undefined;
        }
    }
    
    async saveClientInformation(info: any) {
        const infoFile = getFilePath(this.storageDir, SESSION_KEYS.CLIENT_INFO);
        await fs.writeFile(infoFile, JSON.stringify(info), 'utf8');
    }
    
    async tokens(): Promise<OAuthTokens | undefined> {
        try {
            const tokenFile = getFilePath(this.storageDir, SESSION_KEYS.SESSION_TOKEN);
            const data = await fs.readFile(tokenFile, 'utf8');
            return JSON.parse(data) as OAuthTokens; // TODO: check for await OAuthTokensSchema.parseAsync(JSON.parse(tokens))
        } catch (error) {
            return undefined;
        }
    }
    
    async saveTokens(tokens: OAuthTokens): Promise<void> {
        const tokenFile = getFilePath(this.storageDir, SESSION_KEYS.SESSION_TOKEN);
        await fs.writeFile(tokenFile, JSON.stringify(tokens), 'utf8');
    }
    
    async redirectToAuthorization(): Promise<void> {
        throw new Error('Redirect not supported in headless mode. Use authorizeHeadless() instead.');
    }
    
    async saveCodeVerifier(verifier: string): Promise<void> {
        const verifierFile = getFilePath(this.storageDir, SESSION_KEYS.CODE_VERIFIER);
        await fs.writeFile(verifierFile, verifier, 'utf8');
    }
    
    async codeVerifier(): Promise<string> {
        try {
            const verifierFile = getFilePath(this.storageDir, SESSION_KEYS.CODE_VERIFIER);
            const verifier = await fs.readFile(verifierFile, 'utf8');
            if (!verifier) {
                throw new Error("No code verifier found");
            }
            return verifier;
        } catch (error) {
            throw new Error("No code verifier found");
        }
    }
    
    /**
     * Save device code to storage
     */
    private async saveDeviceCode(deviceCode: string): Promise<void> {
        this._deviceCode = deviceCode;
        const deviceCodeFile = getFilePath(this.storageDir, SESSION_KEYS.DEVICE_CODE);
        await fs.writeFile(deviceCodeFile, deviceCode, 'utf8');
    }
    
    /**
     * Get device code from storage
     */
    private async getDeviceCode(): Promise<string | undefined> {
        if (this._deviceCode) {
            return this._deviceCode;
        }
        
        try {
            const deviceCodeFile = getFilePath(this.storageDir, SESSION_KEYS.DEVICE_CODE);
            return await fs.readFile(deviceCodeFile, 'utf8');
        } catch (error) {
            return undefined;
        }
    }
    
    /**
     * Clear device code from storage
     */
    private async clearDeviceCode(): Promise<void> {
        this._deviceCode = undefined;
        try {
            const deviceCodeFile = getFilePath(this.storageDir, SESSION_KEYS.DEVICE_CODE);
            await fs.unlink(deviceCodeFile);
        } catch (error) {
            // Ignore errors if file doesn't exist
        }
    }
    
    /**
     * Authorize in headless mode using device flow
     * @returns Device authorization information
     */
    async authorizeHeadless(): Promise<{
        user_code: string;
        verification_uri: string;
        verification_uri_complete: string;
        device_code: string;
        expires_in: number;
        interval: number;
    }> {
        const clientInfo = await this.clientInformation();
        
        if (!clientInfo?.client_id) {
            throw new Error("No client information available");
        }
        
        // Request device authorization
        const authUrl = new URL(ENDPOINTS.DEVICE_AUTHORIZE, this.serverUrl);
        console.log('Requesting device authorization from:', authUrl.toString());
        
        const response = await fetch(authUrl.toString(), {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                client_id: clientInfo.client_id
            })
        });
        
        const responseText = await response.text();
        
        if (!response.ok) {
            throw new Error(`Device authorization failed: ${response.status} ${response.statusText}`);
        }
        
        const deviceAuth = JSON.parse(responseText);
        
        // Save device code for polling
        await this.saveDeviceCode(deviceAuth.device_code);
        
        return deviceAuth;
    }
    
    /**
     * Poll for tokens until device is authorized
     * @param options Polling options
     * @returns Promise that resolves when authorized with the token result
     */
    async pollForAuthorization({
        deviceCode,
        interval = 50,
        timeout = 300, // 5 minutes default timeout
        onPending,
        onError
    }: {
        deviceCode?: string;
        interval?: number;
        timeout?: number;
        onPending?: () => void;
        onError?: (error: string) => void;
    } = {}): Promise<OAuthTokens> {
        const clientInfo = await this.clientInformation();
        if (!clientInfo?.client_id) {
            throw new Error("No client information available");
        }
        
        // Get device code from storage if not provided
        if (!deviceCode) {
            deviceCode = await this.getDeviceCode();
            if (!deviceCode) {
                throw new Error("No device code available");
            }
        }
        
        const tokenUrl = new URL(ENDPOINTS.DEVICE_TOKEN, this.serverUrl);
        const startTime = Date.now();
        const maxTime = startTime + (timeout * 1000);
        
        // Keep polling until timeout or success
        while (Date.now() < maxTime) {
            // Wait for the specified interval
            await new Promise(resolve => setTimeout(resolve, interval * 1000));
            
            try {
                const response = await fetch(tokenUrl.toString(), {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    },
                    body: JSON.stringify({
                        client_id: clientInfo.client_id,
                        device_code: deviceCode
                    })
                });
                
                const data = await response.json();
                
                if (!response.ok) {
                    // Handle expected errors
                    if (data.error === 'authorization_pending') {
                        // Still waiting for user authorization
                        if (onPending) onPending();
                        continue;
                    } else if (data.error === 'slow_down') {
                        // Need to slow down polling
                        interval += 5;
                        continue;
                    } else if (data.error === 'expired_token') {
                        if (onError) onError('Authorization request expired');
                        throw new Error('Authorization request expired');
                    } else {
                        if (onError) onError(data.error_description || data.error);
                        throw new Error(data.error_description || data.error);
                    }
                }
                
                // Success! We have tokens
                await this.saveTokens(data);
                
                // Clear device code
                await this.clearDeviceCode();
                
                return data;
            } catch (error) {
                if (error instanceof Error && error.message === 'Authorization request expired') {
                    throw error;
                }
                
                // Network or other errors - wait and retry
                console.error("Error polling for authorization:", error);
                if (onError) onError(`Network error: ${error}`);
            }
        }
        
        throw new Error('Authorization timed out');
    }

    get clientMetadata() {
        return {
            client_name: 'Mash Headless Client',
            redirect_uris: [this.redirectUrl.toString()],
            grant_types: ['authorization_code', 'device_code']
        };
    }
} 