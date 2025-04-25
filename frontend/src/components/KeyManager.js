import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';

const KeyManager = () => {
    const [keys, setKeys] = useState([]);
    const [loading, setLoading] = useState(true);
    const [selectedKey, setSelectedKey] = useState(null);
    const [keyFormOpen, setKeyFormOpen] = useState(false);
    const [formType, setFormType] = useState('rsa'); // 'rsa', 'ec', 'hmac'
    const [keyName, setKeyName] = useState('');
    const [keySize, setKeySize] = useState(2048);
    const [curve, setCurve] = useState('P-256');
    const [isPublic, setIsPublic] = useState(false);
    const [formSubmitting, setFormSubmitting] = useState(false);
    
    const { addToast } = useToast();
    const { isAuthenticated } = useAuth();
    
    const fetchKeys = useCallback(async () => {
        setLoading(true);
        try {
            const response = await axios.get('/api/keys');
            setKeys(response.data.keys || []);
        } catch (error) {
            console.error('Error fetching keys:', error);
            addToast('Failed to load keys. Please try again.', 'error');
        } finally {
            setLoading(false);
        }
    }, [addToast]);
    
    useEffect(() => {
        if (isAuthenticated) {
            fetchKeys();
        }
    }, [isAuthenticated, fetchKeys]);
    
    const handleKeySelect = (key) => {
        setSelectedKey(key);
    };
    
    const openKeyForm = (type) => {
        setFormType(type);
        setKeyName('');
        setKeySize(type === 'rsa' ? 2048 : 32);
        setCurve('P-256');
        setIsPublic(false);
        setKeyFormOpen(true);
    };
    
    const closeKeyForm = () => {
        setKeyFormOpen(false);
    };
    
    const handleSubmit = async (e) => {
        e.preventDefault();
        
        if (!keyName.trim()) {
            addToast('Key name is required', 'error');
            return;
        }
        
        setFormSubmitting(true);
        
        try {
            let endpoint;
            let payload = {
                name: keyName,
                is_public: isPublic
            };
            
            switch (formType) {
                case 'rsa':
                    endpoint = '/api/keys/generate-rsa';
                    payload.key_size = keySize;
                    break;
                case 'ec':
                    endpoint = '/api/keys/generate-ec';
                    payload.curve = curve;
                    break;
                case 'hmac':
                    endpoint = '/api/keys/generate-hmac';
                    payload.key_size = keySize;
                    break;
                default:
                    throw new Error('Invalid key type');
            }
            
            const response = await axios.post(endpoint, payload);
            
            addToast(`${formType.toUpperCase()} key created successfully`, 'success');
            closeKeyForm();
            fetchKeys();
            
            // Select the newly created key
            if (response.data.key_id) {
                // We might need to fetch the complete key details separately
                const keyResponse = await axios.get(`/api/keys/${response.data.key_id}`);
                setSelectedKey(keyResponse.data.key);
            }
        } catch (error) {
            console.error('Error creating key:', error);
            addToast(`Failed to create key: ${error.response?.data?.error || 'Unknown error'}`, 'error');
        } finally {
            setFormSubmitting(false);
        }
    };
    
    const deleteKey = async (keyId) => {
        if (!window.confirm('Are you sure you want to delete this key? This action cannot be undone.')) {
            return;
        }
        
        try {
            await axios.delete(`/api/keys/${keyId}`);
            addToast('Key deleted successfully', 'success');
            
            // Update UI
            if (selectedKey && selectedKey.id === keyId) {
                setSelectedKey(null);
            }
            
            fetchKeys();
        } catch (error) {
            console.error('Error deleting key:', error);
            addToast(`Failed to delete key: ${error.response?.data?.error || 'Unknown error'}`, 'error');
        }
    };
    
    const formatDate = (dateString) => {
        const date = new Date(dateString);
        return date.toLocaleString();
    };
    
    const getKeyTypeIcon = (type) => {
        switch (type.toLowerCase()) {
            case 'rsa':
                return '🔐';
            case 'ec':
                return '🔑';
            case 'hmac':
                return '🔒';
            default:
                return '🗝️';
        }
    };
    
    return (
        <div className="key-manager">
            <div className="key-manager-header">
                <h1>Key Manager</h1>
                <p className="lead">Create and manage cryptographic keys for JWT operations</p>
            </div>
            
            <div className="key-actions">
                <button 
                    className="btn btn-primary" 
                    onClick={() => openKeyForm('rsa')}
                >
                    Generate RSA Key
                </button>
                <button 
                    className="btn btn-primary" 
                    onClick={() => openKeyForm('ec')}
                >
                    Generate EC Key
                </button>
                <button 
                    className="btn btn-primary" 
                    onClick={() => openKeyForm('hmac')}
                >
                    Generate HMAC Secret
                </button>
            </div>
            
            {loading ? (
                <div className="loading-container">
                    <div className="spinner"></div>
                    <p>Loading keys...</p>
                </div>
            ) : (
                <div className="key-content">
                    <div className="key-list">
                        <h2>Your Keys</h2>
                        {keys.length === 0 ? (
                            <div className="empty-state">
                                <p>You don't have any keys yet.</p>
                                <p>Use the buttons above to generate new keys.</p>
                            </div>
                        ) : (
                            <div className="keys-container">
                                {keys.map(key => (
                                    <div 
                                        key={key.id} 
                                        className={`key-item ${selectedKey && selectedKey.id === key.id ? 'selected' : ''}`}
                                        onClick={() => handleKeySelect(key)}
                                    >
                                        <div className="key-icon">{getKeyTypeIcon(key.key_type)}</div>
                                        <div className="key-info">
                                            <h3>{key.name}</h3>
                                            <div className="key-meta">
                                                <span className="key-type">{key.key_type}</span>
                                                <span className="key-algo">{key.algorithm}</span>
                                            </div>
                                            <div className="key-date">
                                                Created: {formatDate(key.created_at)}
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                    
                    <div className="key-details">
                        {selectedKey ? (
                            <>
                                <div className="key-header">
                                    <h2>{selectedKey.name}</h2>
                                    <button 
                                        className="btn btn-danger"
                                        onClick={() => deleteKey(selectedKey.id)}
                                    >
                                        Delete
                                    </button>
                                </div>
                                
                                <div className="key-properties">
                                    <div className="key-property">
                                        <span className="property-label">Type:</span>
                                        <span className="property-value">{selectedKey.key_type}</span>
                                    </div>
                                    <div className="key-property">
                                        <span className="property-label">Algorithm:</span>
                                        <span className="property-value">{selectedKey.algorithm}</span>
                                    </div>
                                    <div className="key-property">
                                        <span className="property-label">Created:</span>
                                        <span className="property-value">{formatDate(selectedKey.created_at)}</span>
                                    </div>
                                    <div className="key-property">
                                        <span className="property-label">Public:</span>
                                        <span className="property-value">{selectedKey.is_public ? 'Yes' : 'No'}</span>
                                    </div>
                                </div>
                                
                                {selectedKey.key_data && (
                                    <div className="key-data">
                                        <h3>Key Data</h3>
                                        <div className="key-code">
                                            <pre>{selectedKey.key_data}</pre>
                                        </div>
                                    </div>
                                )}
                                
                                <div className="key-actions">
                                    <button className="btn btn-secondary">Export Public Key</button>
                                    <button className="btn btn-secondary">Use in Verifier</button>
                                </div>
                            </>
                        ) : (
                            <div className="no-key-selected">
                                <p>Select a key to view details</p>
                            </div>
                        )}
                    </div>
                </div>
            )}
            
            {keyFormOpen && (
                <div className="key-form-modal">
                    <div className="key-form-content">
                        <div className="key-form-header">
                            <h2>Generate {formType.toUpperCase()} Key</h2>
                            <button className="close-btn" onClick={closeKeyForm}>×</button>
                        </div>
                        
                        <form onSubmit={handleSubmit}>
                            <div className="form-group">
                                <label htmlFor="keyName">Key Name</label>
                                <input
                                    type="text"
                                    id="keyName"
                                    value={keyName}
                                    onChange={(e) => setKeyName(e.target.value)}
                                    required
                                    disabled={formSubmitting}
                                />
                            </div>
                            
                            {formType === 'rsa' && (
                                <div className="form-group">
                                    <label htmlFor="keySize">Key Size (bits)</label>
                                    <select
                                        id="keySize"
                                        value={keySize}
                                        onChange={(e) => setKeySize(Number(e.target.value))}
                                        disabled={formSubmitting}
                                    >
                                        <option value={2048}>2048</option>
                                        <option value={3072}>3072</option>
                                        <option value={4096}>4096</option>
                                    </select>
                                </div>
                            )}
                            
                            {formType === 'ec' && (
                                <div className="form-group">
                                    <label htmlFor="curve">Curve</label>
                                    <select
                                        id="curve"
                                        value={curve}
                                        onChange={(e) => setCurve(e.target.value)}
                                        disabled={formSubmitting}
                                    >
                                        <option value="P-256">P-256</option>
                                        <option value="P-384">P-384</option>
                                        <option value="P-521">P-521</option>
                                    </select>
                                </div>
                            )}
                            
                            {formType === 'hmac' && (
                                <div className="form-group">
                                    <label htmlFor="keySize">Key Size (bytes)</label>
                                    <select
                                        id="keySize"
                                        value={keySize}
                                        onChange={(e) => setKeySize(Number(e.target.value))}
                                        disabled={formSubmitting}
                                    >
                                        <option value={32}>32 (256 bits - for HS256)</option>
                                        <option value={48}>48 (384 bits - for HS384)</option>
                                        <option value={64}>64 (512 bits - for HS512)</option>
                                    </select>
                                </div>
                            )}
                            
                            <div className="form-check">
                                <input
                                    type="checkbox"
                                    id="isPublic"
                                    checked={isPublic}
                                    onChange={(e) => setIsPublic(e.target.checked)}
                                    disabled={formSubmitting}
                                />
                                <label htmlFor="isPublic">
                                    Make this key public (visible to other users)
                                </label>
                            </div>
                            
                            <div className="form-actions">
                                <button
                                    type="button"
                                    className="btn btn-secondary"
                                    onClick={closeKeyForm}
                                    disabled={formSubmitting}
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    className="btn btn-primary"
                                    disabled={formSubmitting}
                                >
                                    {formSubmitting ? 'Generating...' : 'Generate Key'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
};

export default KeyManager; 