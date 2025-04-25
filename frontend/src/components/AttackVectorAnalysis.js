import React, { useState, useEffect } from 'react';

const AttackVectorAnalysis = () => {
    const [attackVectors, setAttackVectors] = useState([]);
    const [loading, setLoading] = useState(true);
    const [selectedVector, setSelectedVector] = useState(null);
    
    useEffect(() => {
        // In a real app, this would fetch from an API
        const fetchAttackVectors = async () => {
            try {
                // Uncomment and use in production
                // const response = await axios.get('/api/attack-vectors');
                // setAttackVectors(response.data);
                
                // Simulated data for development
                setTimeout(() => {
                    setAttackVectors([
                        {
                            id: 1,
                            name: 'Algorithm None Attack',
                            description: 'Exploits JWTs that accept "none" as a valid algorithm.',
                            riskLevel: 'critical',
                            detectionDifficulty: 'low',
                            prevalence: 'medium',
                            mitigation: 'Always validate the algorithm specified in the header and reject tokens with "none" algorithm.',
                            example: 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.'
                        },
                        {
                            id: 2,
                            name: 'Algorithm Confusion',
                            description: 'Forces the server to verify an RSA-signed token with an HMAC algorithm, using the public key as the HMAC secret.',
                            riskLevel: 'high',
                            detectionDifficulty: 'medium',
                            prevalence: 'high',
                            mitigation: 'Explicitly specify and validate the expected algorithm for token verification.',
                            example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
                        },
                        {
                            id: 3,
                            name: 'Weak Secret Keys',
                            description: 'Uses brute force to crack weakly generated HMAC secrets.',
                            riskLevel: 'high',
                            detectionDifficulty: 'high',
                            prevalence: 'high',
                            mitigation: 'Use strong, randomly generated keys with sufficient entropy (at least 256 bits).',
                            example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
                        },
                        {
                            id: 4,
                            name: 'Missing Signature Validation',
                            description: 'Exploits implementations that extract claims from a JWT without verifying the signature.',
                            riskLevel: 'critical',
                            detectionDifficulty: 'medium',
                            prevalence: 'medium',
                            mitigation: 'Always verify JWT signatures before trusting or using any claims from the token.',
                            example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid_signature'
                        },
                        {
                            id: 5,
                            name: 'Key ID (kid) Injection',
                            description: 'Manipulates the "kid" header parameter to force the server to use an attacker-controlled key for verification.',
                            riskLevel: 'high',
                            detectionDifficulty: 'high',
                            prevalence: 'medium',
                            mitigation: 'Validate and sanitize the "kid" parameter, and use a whitelist of allowed key identifiers.',
                            example: 'eyJhbGciOiJIUzI1NiIsImtpZCI6ImZpbGU6Ly8vZXRjL3Bhc3N3ZCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
                        }
                    ]);
                    setLoading(false);
                }, 800);
            } catch (error) {
                console.error('Error fetching attack vectors:', error);
                setLoading(false);
            }
        };
        
        fetchAttackVectors();
    }, []);
    
    const handleVectorSelect = (vector) => {
        setSelectedVector(vector);
    };
    
    const getRiskLevelClass = (level) => {
        switch (level.toLowerCase()) {
            case 'critical':
                return 'risk-critical';
            case 'high':
                return 'risk-high';
            case 'medium':
                return 'risk-medium';
            case 'low':
                return 'risk-low';
            default:
                return '';
        }
    };
    
    return (
        <div className="attack-vector-analysis">
            <div className="av-header">
                <h1>JWT Attack Vector Analysis</h1>
                <p className="lead">Common attack vectors against JWT implementations and their mitigations</p>
            </div>
            
            {loading ? (
                <div className="loading-container">
                    <div className="spinner"></div>
                    <p>Loading attack vectors...</p>
                </div>
            ) : (
                <div className="av-content">
                    <div className="av-list">
                        <h2>Attack Vectors</h2>
                        <div className="vectors-list">
                            {attackVectors.map(vector => (
                                <div 
                                    key={vector.id}
                                    className={`vector-item ${selectedVector && selectedVector.id === vector.id ? 'selected' : ''}`}
                                    onClick={() => handleVectorSelect(vector)}
                                >
                                    <h3>{vector.name}</h3>
                                    <div className={`risk-badge ${getRiskLevelClass(vector.riskLevel)}`}>
                                        {vector.riskLevel}
                                    </div>
                                    <p className="vector-preview">{vector.description.substring(0, 80)}...</p>
                                </div>
                            ))}
                        </div>
                    </div>
                    
                    <div className="av-details">
                        {selectedVector ? (
                            <>
                                <h2>{selectedVector.name}</h2>
                                <div className="av-risk-info">
                                    <div className={`risk-indicator ${getRiskLevelClass(selectedVector.riskLevel)}`}>
                                        Risk Level: {selectedVector.riskLevel}
                                    </div>
                                    <div className="av-meta">
                                        <span>Detection Difficulty: {selectedVector.detectionDifficulty}</span>
                                        <span>Prevalence: {selectedVector.prevalence}</span>
                                    </div>
                                </div>
                                
                                <div className="av-description">
                                    <h3>Description</h3>
                                    <p>{selectedVector.description}</p>
                                </div>
                                
                                <div className="av-mitigation">
                                    <h3>Mitigation</h3>
                                    <p>{selectedVector.mitigation}</p>
                                </div>
                                
                                <div className="av-example">
                                    <h3>Example Token</h3>
                                    <div className="token-example">
                                        <code>{selectedVector.example}</code>
                                    </div>
                                </div>
                                
                                <div className="av-actions">
                                    <button className="btn btn-primary">Test This Attack</button>
                                    <button className="btn btn-secondary">View Detailed Guide</button>
                                </div>
                            </>
                        ) : (
                            <div className="no-selection">
                                <p>Select an attack vector to view details</p>
                            </div>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
};

export default AttackVectorAnalysis; 