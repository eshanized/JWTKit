import React, { useState } from 'react';
import { useTheme } from '../context/ThemeContext';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';

const Settings = () => {
    const { theme, toggleTheme } = useTheme();
    const { user } = useAuth();
    const { addToast } = useToast();
    
    const [defaultAlgorithm, setDefaultAlgorithm] = useState('HS256');
    const [defaultExpiration, setDefaultExpiration] = useState('1h');
    const [autoSaveTokens, setAutoSaveTokens] = useState(false);
    const [confirmDangerousActions, setConfirmDangerousActions] = useState(true);
    const [showAdvancedOptions, setShowAdvancedOptions] = useState(false);
    const [saving, setSaving] = useState(false);
    
    const handleSubmit = async (e) => {
        e.preventDefault();
        setSaving(true);
        
        try {
            // Simulating API call to save settings
            await new Promise(resolve => setTimeout(resolve, 800));
            
            // In a real app, you would use axios to save the settings
            // await axios.post('/api/user/settings', {
            //     defaultAlgorithm,
            //     defaultExpiration,
            //     autoSaveTokens,
            //     confirmDangerousActions,
            //     showAdvancedOptions,
            //     theme
            // });
            
            addToast('Settings saved successfully', 'success');
        } catch (error) {
            console.error('Error saving settings:', error);
            addToast('Failed to save settings', 'error');
        } finally {
            setSaving(false);
        }
    };
    
    return (
        <div className="settings-container">
            <div className="settings-header">
                <h1>Settings</h1>
                <p className="lead">Customize your JWT testing environment</p>
            </div>
            
            <div className="settings-content">
                <form onSubmit={handleSubmit}>
                    <div className="settings-section">
                        <h2>Appearance</h2>
                        <div className="form-group">
                            <label>Theme</label>
                            <div className="theme-selector">
                                <button
                                    type="button"
                                    className={`theme-option ${theme === 'light' ? 'active' : ''}`}
                                    onClick={() => theme !== 'light' && toggleTheme()}
                                >
                                    <span className="theme-icon">☀️</span>
                                    Light
                                </button>
                                <button
                                    type="button"
                                    className={`theme-option ${theme === 'dark' ? 'active' : ''}`}
                                    onClick={() => theme !== 'dark' && toggleTheme()}
                                >
                                    <span className="theme-icon">🌙</span>
                                    Dark
                                </button>
                            </div>
                        </div>
                    </div>
                    
                    <div className="settings-section">
                        <h2>JWT Defaults</h2>
                        <div className="form-group">
                            <label htmlFor="defaultAlgorithm">Default Signing Algorithm</label>
                            <select
                                id="defaultAlgorithm"
                                value={defaultAlgorithm}
                                onChange={(e) => setDefaultAlgorithm(e.target.value)}
                            >
                                <option value="HS256">HS256 - HMAC with SHA-256</option>
                                <option value="HS384">HS384 - HMAC with SHA-384</option>
                                <option value="HS512">HS512 - HMAC with SHA-512</option>
                                <option value="RS256">RS256 - RSA with SHA-256</option>
                                <option value="RS384">RS384 - RSA with SHA-384</option>
                                <option value="RS512">RS512 - RSA with SHA-512</option>
                                <option value="ES256">ES256 - ECDSA with SHA-256</option>
                                <option value="ES384">ES384 - ECDSA with SHA-384</option>
                                <option value="ES512">ES512 - ECDSA with SHA-512</option>
                            </select>
                        </div>
                        
                        <div className="form-group">
                            <label htmlFor="defaultExpiration">Default Token Expiration</label>
                            <select
                                id="defaultExpiration"
                                value={defaultExpiration}
                                onChange={(e) => setDefaultExpiration(e.target.value)}
                            >
                                <option value="15m">15 minutes</option>
                                <option value="30m">30 minutes</option>
                                <option value="1h">1 hour</option>
                                <option value="2h">2 hours</option>
                                <option value="6h">6 hours</option>
                                <option value="12h">12 hours</option>
                                <option value="1d">1 day</option>
                                <option value="7d">7 days</option>
                                <option value="30d">30 days</option>
                            </select>
                        </div>
                    </div>
                    
                    <div className="settings-section">
                        <h2>Behavior</h2>
                        <div className="form-check">
                            <input
                                type="checkbox"
                                id="autoSaveTokens"
                                checked={autoSaveTokens}
                                onChange={(e) => setAutoSaveTokens(e.target.checked)}
                            />
                            <label htmlFor="autoSaveTokens">
                                Automatically save tokens to history
                            </label>
                        </div>
                        
                        <div className="form-check">
                            <input
                                type="checkbox"
                                id="confirmDangerousActions"
                                checked={confirmDangerousActions}
                                onChange={(e) => setConfirmDangerousActions(e.target.checked)}
                            />
                            <label htmlFor="confirmDangerousActions">
                                Confirm dangerous actions (deleting keys, etc.)
                            </label>
                        </div>
                        
                        <div className="form-check">
                            <input
                                type="checkbox"
                                id="showAdvancedOptions"
                                checked={showAdvancedOptions}
                                onChange={(e) => setShowAdvancedOptions(e.target.checked)}
                            />
                            <label htmlFor="showAdvancedOptions">
                                Show advanced options in all tools
                            </label>
                        </div>
                    </div>
                    
                    <div className="settings-section">
                        <h2>Account</h2>
                        <div className="account-info">
                            <p><strong>Username:</strong> {user?.username || 'Not logged in'}</p>
                            <p><strong>Email:</strong> {user?.email || 'No email provided'}</p>
                            <p><strong>Role:</strong> {user?.role || 'User'}</p>
                        </div>
                        <div className="account-actions">
                            <button type="button" className="btn btn-secondary">
                                Change Password
                            </button>
                            <button type="button" className="btn btn-danger">
                                Delete Account
                            </button>
                        </div>
                    </div>
                    
                    <div className="form-actions">
                        <button
                            type="submit"
                            className="btn btn-primary"
                            disabled={saving}
                        >
                            {saving ? 'Saving...' : 'Save Settings'}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default Settings; 