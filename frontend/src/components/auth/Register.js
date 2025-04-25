import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';
import api from '../../services/api';
import './auth.css';

const Register = () => {
    const [formData, setFormData] = useState({
        username: '',
        email: '',
        password: '',
        confirmPassword: ''
    });
    const [error, setError] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const navigate = useNavigate();

    const { username, email, password, confirmPassword } = formData;

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData({
            ...formData,
            [name]: value
        });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');

        // Validate form
        if (!username || !email || !password) {
            setError('All fields are required');
            return;
        }

        if (password !== confirmPassword) {
            setError('Passwords do not match');
            return;
        }

        if (password.length < 8) {
            setError('Password must be at least 8 characters long');
            return;
        }

        try {
            setIsLoading(true);
            
            await api.post('/auth/register', {
                username,
                email,
                password
            });
            
            toast.success('Registration successful! Please log in.');
            navigate('/login');
        } catch (err) {
            console.error('Registration error:', err);
            setError(
                err.response?.data?.message || 
                'Registration failed. Please try again.'
            );
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="register-container">
            <div className="register-card">
                <h2>Create Account</h2>
                <p className="register-subtitle">Join JWTKit and test your JWT implementations</p>
                
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
                            name="username"
                            className="form-control"
                            value={username}
                            onChange={handleChange}
                            placeholder="Choose a username"
                            autoComplete="username"
                            disabled={isLoading}
                        />
                    </div>
                    
                    <div className="form-group">
                        <label htmlFor="email">Email</label>
                        <input
                            type="email"
                            id="email"
                            name="email"
                            className="form-control"
                            value={email}
                            onChange={handleChange}
                            placeholder="Enter your email"
                            autoComplete="email"
                            disabled={isLoading}
                        />
                    </div>
                    
                    <div className="form-group">
                        <label htmlFor="password">Password</label>
                        <input
                            type="password"
                            id="password"
                            name="password"
                            className="form-control"
                            value={password}
                            onChange={handleChange}
                            placeholder="Create a password"
                            autoComplete="new-password"
                            disabled={isLoading}
                        />
                    </div>
                    
                    <div className="form-group">
                        <label htmlFor="confirmPassword">Confirm Password</label>
                        <input
                            type="password"
                            id="confirmPassword"
                            name="confirmPassword"
                            className="form-control"
                            value={confirmPassword}
                            onChange={handleChange}
                            placeholder="Confirm your password"
                            autoComplete="new-password"
                            disabled={isLoading}
                        />
                    </div>
                    
                    <button 
                        type="submit" 
                        className="register-btn" 
                        disabled={isLoading}
                    >
                        {isLoading ? 'Creating Account...' : 'Create Account'}
                    </button>
                </form>
                
                <div className="register-footer">
                    Already have an account? <Link to="/login">Sign In</Link>
                </div>
            </div>
        </div>
    );
};

export default Register; 