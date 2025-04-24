import express from 'express';
import { GitHubServerAuthProvider } from './auth/GHAuthProvider.js';

export function setupDeviceFlowRoutes(authProvider: GitHubServerAuthProvider) {
    const router = express.Router();
    
    // Device token polling endpoint
    router.post('/device/token', async (req, res) => {
        try {
            const { client_id, device_code } = req.body;
            
            if (!client_id || !device_code) {
                return res.status(400).json({
                    error: 'invalid_request',
                    error_description: 'Missing required parameters'
                });
            }
            
            // Get client information
            const client = authProvider.clientsStore.getClient(client_id);
            if (!client) {
                return res.status(400).json({
                    error: 'invalid_client',
                    error_description: 'Client not found'
                });
            }
            
            // Check device code status
            const result = await authProvider.checkDeviceCodeStatus(device_code);
            
            // Return result (either tokens or error information)
            if ('error' in result) {
                return res.status(result.error === 'authorization_pending' ? 400 : 401).json(result);
            }
            
            res.json(result);
        } catch (error) {
            console.error("Device token error:", error);
            res.status(500).json({
                error: 'server_error',
                error_description: String(error)
            });
        }
    });
    
    // Simple UI for activation
    router.get('/activate', (req, res) => {
        const { user_code } = req.query;
        // In a real implementation, we would render an HTML template
        res.send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Activate Your Device</title>
                <style>
                    body { font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; }
                    .code-form { margin: 20px 0; }
                    input { font-size: 18px; padding: 8px; letter-spacing: 2px; width: 120px; }
                    .success { color: green; padding: 20px; border: 1px solid green; }
                    .error { color: red; padding: 20px; border: 1px solid red; }
                </style>
            </head>
            <body>
                <h1>Device Activation</h1>
                
                <p>Enter the code displayed on your device to authorize access:</p>
                
                <form class="code-form" method="POST" action="/auth/activate">
                    <input type="text" name="user_code" value="${user_code || ''}" placeholder="XXXX-XXXX" required>
                    <button type="submit">Activate</button>
                </form>
            </body>
            </html>
        `);
    });
    
    // Device authorization endpoint
    router.post('/device/authorize', async (req, res) => {
        try {
            const { client_id } = req.body;
            console.log('Device authorize request received'); 
            
            if (!client_id) {
                console.log('Missing client_id in request');
                return res.status(400).json({
                    error: 'invalid_request',
                    error_description: 'Missing client_id parameter'
                });
            }
            
            // Get client information
            const client = authProvider.clientsStore.getClient(client_id);
            if (!client) {
                console.log('Client not found:', client_id);
                return res.status(400).json({
                    error: 'invalid_client',
                    error_description: 'Client not found'
                });
            }
            
            // Initiate device flow
            const deviceAuthData = await authProvider.initiateDeviceFlow(client_id);
            
            res.json(deviceAuthData);
        } catch (error) {
            console.error("Device authorization error:", error);
            res.status(500).json({
                error: 'server_error',
                error_description: String(error)
            });
        }
    });
    
    return router;
} 