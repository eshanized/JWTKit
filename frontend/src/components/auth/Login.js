import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';
import api from '../../services/api';
import './auth.css';

const Login = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');

        // Validate form
        if (!username || !password) {
            setError('Username and password are required');
            return;
        }

        try {
            setIsLoading(true);
            
            const response = await api.post('/api/auth/login', { username, password });
            
            // Save token and user info
            localStorage.setItem('token', response.data.access_token);
            localStorage.setItem('user', JSON.stringify(response.data.user));
            
            // Notify success
            toast.success('Login successful!');
            
            // Redirect to dashboard
            navigate('/dashboard');
        } catch (err) {
            console.error('Login error:', err);
            setError(
                err.response?.data?.error || 
                'Login failed. Please check your credentials.'
            );
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="login-container">
            <div className="login-card">
                <h2>Welcome Back</h2>
                <p className="login-subtitle">Sign in to your JWTKit account</p>
                
                {error && (
                    <div className="alert alert-danger">
                        {error}
                    </div>
                )}
                
                <form onSubmit={handleSubmit}>
                    <div className="form-group">
                        <label htmlFor="username">Username</label>
                        <input
                            type="text"
                            id="username"
                            className="form-control"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            placeholder="Enter your username"
                            autoComplete="username"
                            disabled={isLoading}
                        />
                    </div>
                    
                    <div className="form-group">
                        <label htmlFor="password">Password</label>
                        <input
                            type="password"
                            id="password"
                            className="form-control"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            placeholder="Enter your password"
                            autoComplete="current-password"
                            disabled={isLoading}
                        />
                    </div>
                    
                    <button 
                        type="submit" 
                        className="login-btn" 
                        disabled={isLoading}
                    >
                        {isLoading ? 'Signing in...' : 'Sign In'}
                    </button>
                </form>
                
                <div className="login-footer">
                    Don't have an account? <Link to="/register">Register</Link>
                </div>
            </div>
        </div>
    );
};

export default Login; 