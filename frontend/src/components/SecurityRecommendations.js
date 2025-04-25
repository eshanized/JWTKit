import React, { useState } from 'react';

const SecurityRecommendations = () => {
    const [selectedCategory, setSelectedCategory] = useState('all');
    
    const recommendations = [
        {
            id: 1,
            category: 'general',
            title: 'Use Strong Signature Algorithms',
            description: 'Prefer RS256 (RSA Signature with SHA-256) over HS256 (HMAC with SHA-256) when possible. RSA provides better security properties and key management options.',
            severity: 'high'
        },
        {
            id: 2,
            category: 'header',
            title: 'Include Algorithm in Header',
            description: 'Always explicitly set the "alg" parameter in the JWT header to prevent algorithm confusion attacks.',
            severity: 'high'
        },
        {
            id: 3,
            category: 'claims',
            title: 'Set Reasonable Expiration',
            description: 'Always include an "exp" (expiration time) claim with a reasonable lifetime. For most applications, tokens should expire in minutes or hours, not days.',
            severity: 'medium'
        },
        {
            id: 4,
            category: 'general',
            title: 'Use Strong Keys',
            description: 'Use keys with adequate entropy: 256-bit keys for HMAC, 2048-bit keys (or stronger) for RSA, and appropriate curves for EC algorithms.',
            severity: 'high'
        },
        {
            id: 5,
            category: 'claims',
            title: 'Include Issuer and Audience',
            description: 'Add "iss" (issuer) and "aud" (audience) claims to your tokens to limit where they can be used and prevent token reuse across services.',
            severity: 'medium'
        },
        {
            id: 6,
            category: 'validation',
            title: 'Validate All Claims',
            description: 'Always validate all claims in a token, including "iss", "aud", "exp", "nbf", and any custom claims your application requires.',
            severity: 'high'
        },
        {
            id: 7,
            category: 'implementation',
            title: 'Implement JWKs Rotation',
            description: 'Rotate your signing keys regularly and implement a JWKs (JSON Web Key Set) endpoint to share your public keys securely.',
            severity: 'medium'
        },
        {
            id: 8,
            category: 'validation',
            title: 'Verify Before Use',
            description: 'Always verify the signature of a JWT before trusting any claims contained within it.',
            severity: 'critical'
        },
        {
            id: 9,
            category: 'implementation',
            title: 'Prevent Token Leakage',
            description: 'Store tokens securely on the client, preferably in memory or secure HTTP-only cookies to prevent XSS attacks.',
            severity: 'high'
        },
        {
            id: 10,
            category: 'claims',
            title: 'Use Nonce Claims',
            description: 'Include a nonce (number used once) claim in tokens used for authentication to prevent replay attacks.',
            severity: 'medium'
        }
    ];
    
    const filterRecommendations = () => {
        if (selectedCategory === 'all') {
            return recommendations;
        }
        return recommendations.filter(rec => rec.category === selectedCategory);
    };
    
    const getSeverityClass = (severity) => {
        switch (severity) {
            case 'critical':
                return 'severity-critical';
            case 'high':
                return 'severity-high';
            case 'medium':
                return 'severity-medium';
            case 'low':
                return 'severity-low';
            default:
                return '';
        }
    };
    
    return (
        <div className="security-recommendations">
            <div className="recommendations-header">
                <h1>JWT Security Recommendations</h1>
                <p className="lead">Best practices to enhance the security of your JWT implementation</p>
            </div>
            
            <div className="filter-container">
                <div className="filter-label">Filter by category:</div>
                <div className="filter-options">
                    <button 
                        className={`filter-btn ${selectedCategory === 'all' ? 'active' : ''}`}
                        onClick={() => setSelectedCategory('all')}
                    >
                        All
                    </button>
                    <button 
                        className={`filter-btn ${selectedCategory === 'general' ? 'active' : ''}`}
                        onClick={() => setSelectedCategory('general')}
                    >
                        General
                    </button>
                    <button 
                        className={`filter-btn ${selectedCategory === 'header' ? 'active' : ''}`}
                        onClick={() => setSelectedCategory('header')}
                    >
                        Header
                    </button>
                    <button 
                        className={`filter-btn ${selectedCategory === 'claims' ? 'active' : ''}`}
                        onClick={() => setSelectedCategory('claims')}
                    >
                        Claims
                    </button>
                    <button 
                        className={`filter-btn ${selectedCategory === 'validation' ? 'active' : ''}`}
                        onClick={() => setSelectedCategory('validation')}
                    >
                        Validation
                    </button>
                    <button 
                        className={`filter-btn ${selectedCategory === 'implementation' ? 'active' : ''}`}
                        onClick={() => setSelectedCategory('implementation')}
                    >
                        Implementation
                    </button>
                </div>
            </div>
            
            <div className="recommendations-list">
                {filterRecommendations().map(recommendation => (
                    <div className="recommendation-card" key={recommendation.id}>
                        <div className={`severity-indicator ${getSeverityClass(recommendation.severity)}`}>
                            {recommendation.severity.toUpperCase()}
                        </div>
                        <h3>{recommendation.title}</h3>
                        <div className="category-tag">{recommendation.category}</div>
                        <p>{recommendation.description}</p>
                    </div>
                ))}
            </div>
        </div>
    );
};

export default SecurityRecommendations; 