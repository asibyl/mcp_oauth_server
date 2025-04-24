import { HeadlessClientOAuthProvider } from './auth/HeadlessClientOAuthProvider.js';

async function main() {
    const serverUrl = 'http://localhost:3000';
    
    // Try a simple health check first
    try {
        console.log('Testing server connection...');
        const healthCheck = await fetch(`${serverUrl}/.well-known/oauth-authorization-server`);
        console.log('Server response status:', healthCheck.status);
        console.log('Server response:', await healthCheck.text());
    } catch (error) {
        console.error('Health check failed:', error);
    }
    
    // Create the provider with server URL
    const authProvider = new HeadlessClientOAuthProvider(serverUrl);
    
    // Register the client first
    try {
        console.log('Registering client...');
        const registrationResponse = await fetch(`${serverUrl}/auth/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify(authProvider.clientMetadata)
        });

        if (!registrationResponse.ok) {
            const errorText = await registrationResponse.text();
            console.error('Registration response:', {
                status: registrationResponse.status,
                statusText: registrationResponse.statusText,
                body: errorText
            });
            throw new Error(`Registration failed: ${registrationResponse.status} ${registrationResponse.statusText}`);
        }
        
        const clientInfo = await registrationResponse.json();
        console.log('Client registered successfully:', clientInfo);
        
        await authProvider.saveClientInformation(clientInfo);
    } catch (error) {
        console.error('Failed to register client:', error);
        process.exit(1);
    }
    
    // Check if we already have tokens
    const tokens = await authProvider.tokens();
    if (tokens) {
        console.log('Already authenticated with tokens:', tokens);
        return;
    }
    
    // Start the headless authorization flow
    console.log('Starting device flow authentication...');
    const deviceAuth = await authProvider.authorizeHeadless();
    
    console.log('\n=== DEVICE ACTIVATION ===');
    console.log(`Please visit: ${deviceAuth.verification_uri}`);
    console.log(`And enter code: ${deviceAuth.user_code}`);
    console.log(`\nOr visit this URL directly: ${deviceAuth.verification_uri_complete}`);
    
    // Poll for authorization
    console.log('\nWaiting for authorization...');
    try {
        const result = await authProvider.pollForAuthorization({
            deviceCode: deviceAuth.device_code,
            interval: deviceAuth.interval,
            onPending: () => process.stdout.write('.'),
            onError: (error) => console.error(`\nError: ${error}`)
        });
        
        console.log('\n\nAuthorization successful!');
        console.log('Tokens:', result);
    } catch (error) {
        console.error('\n\nAuthorization failed:', error);
        process.exit(1);
    }
}

main().catch(console.error); 