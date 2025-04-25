import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Link } from 'react-router-dom';
import { Container, Row, Col } from 'react-bootstrap';
import { useAuth } from '../context/AuthContext';
import './Dashboard.css';

const Dashboard = () => {
    const { isAuthenticated, user } = useAuth();
    const [stats, setStats] = useState({
        tokensDecoded: 0,
        attacksSimulated: 0,
        vulnerabilitiesFound: 0
    });
    const [loading, setLoading] = useState(true);

    // Animate counter effect for statistics
    const animateValue = (start, end, duration, setter, property) => {
        let startTimestamp = null;
        const step = (timestamp) => {
            if (!startTimestamp) startTimestamp = timestamp;
            const progress = Math.min((timestamp - startTimestamp) / duration, 1);
            const value = Math.floor(progress * (end - start) + start);
            
            setter(prevStats => ({
                ...prevStats,
                [property]: value
            }));
            
            if (progress < 1) {
                window.requestAnimationFrame(step);
            }
        };
        window.requestAnimationFrame(step);
    };

    useEffect(() => {
        // Simulate loading stats with animated counters
        const timer = setTimeout(() => {
            setLoading(false);
            animateValue(0, 256, 1500, setStats, 'tokensDecoded');
            animateValue(0, 42, 1500, setStats, 'attacksSimulated');
            animateValue(0, 18, 1500, setStats, 'vulnerabilitiesFound');
        }, 1000);
        
        return () => clearTimeout(timer);
    }, []);

    const features = [
        {
            title: "JWT Decoder",
            description: "Decode and analyze JWT tokens without performing signature verification. Inspect payload and header data easily.",
            link: "/decode",
            icon: "🔍"
        },
        {
            title: "Signature Verifier",
            description: "Verify JWT signatures with multiple algorithms. Support for RSA, HMAC, and Elliptic Curve verification.",
            link: "/verify",
            icon: "✓"
        },
        {
            title: "Vulnerability Scanner",
            description: "Automatically detect common JWT security issues such as weak algorithms, missing claims, or insecure key usage.",
            link: "/vulnerabilities",
            icon: "🛡️"
        },
        {
            title: "Payload Editor",
            description: "Modify token payloads and headers with real-time previews. Test how changes affect token validity and behavior.",
            link: "/modify",
            icon: "✏️"
        },
        {
            title: "Attack Simulator",
            description: "Simulate common JWT attacks including none algorithm, key confusion, and token forgery to test system security.",
            link: "/attack-simulator",
            icon: "⚔️"
        },
        {
            title: "Token Fuzzer",
            description: "Generate variations of tokens for penetration testing. Create multiple token variants with different parameters.",
            link: "/tokens/fuzzer",
            icon: "🔀"
        }
    ];

    return (
        <Container fluid className="dashboard">
            <div className="dashboard-header">
                <h1>Welcome to JWTKit{isAuthenticated ? `, ${user.username}` : ''}</h1>
                <p className="lead">Your comprehensive toolkit for JWT analysis, testing, and security assessment</p>
            </div>

            {!isAuthenticated && (
                <div className="guest-announcement">
                    <h3>Try All Features Without Login</h3>
                    <p>
                        All JWTKit features are now available without logging in! 
                        You can explore every tool and functionality as a guest user.
                    </p>
                    <p>
                        <i className="fas fa-info-circle"></i> <strong>Note:</strong> To save your work, tokens, and scan results, 
                        <Link to="/register"> create an account</Link> or <Link to="/login">log in</Link>.
                    </p>
                </div>
            )}

            {loading ? (
                <div className="loading-spinner">
                    <div className="spinner"></div>
                    <p>Loading dashboard...</p>
                </div>
            ) : (
                <>
                    <div className="stats-container">
                        <div className="stat-card">
                            <h3>Tokens Decoded</h3>
                            <div className="stat-value">{stats.tokensDecoded}</div>
                        </div>
                        <div className="stat-card">
                            <h3>Attacks Simulated</h3>
                            <div className="stat-value">{stats.attacksSimulated}</div>
                        </div>
                        <div className="stat-card">
                            <h3>Vulnerabilities Found</h3>
                            <div className="stat-value">{stats.vulnerabilitiesFound}</div>
                        </div>
                    </div>

                    <h2>Powerful JWT Tools</h2>
                    <div className="features-grid">
                        {features.map((feature, index) => (
                            <div className="feature-card" key={index}>
                                <div className="feature-icon">{feature.icon}</div>
                                <h3>{feature.title}</h3>
                                <p>{feature.description}</p>
                                <Link to={feature.link} className="feature-link">
                                    Try it now →
                                </Link>
                            </div>
                        ))}
                    </div>
                </>
            )}
        </Container>
    );
};

export default Dashboard; 