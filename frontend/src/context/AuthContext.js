import React, { createContext, useState, useContext, useEffect } from 'react';
import axios from 'axios';
import { getCurrentUser } from '../services/api';

// Create context
const AuthContext = createContext(null);

// Provider component
export const AuthProvider = ({ children, value }) => {
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);
    
    // Initialize from provided value (for testing/mocking)
    useEffect(() => {
        if (value) {
            setIsAuthenticated(value.isAuthenticated || false);
            setUser(value.user || null);
            setLoading(false);
        }
    }, [value]);
    
    // Initialize auth state
    useEffect(() => {
        const checkAuth = async () => {
            const token = localStorage.getItem('token');
            
            if (!token) {
                // Set guest user when not authenticated
                const guestUser = getCurrentUser();
                setUser(guestUser);
                setIsAuthenticated(false);
                setLoading(false);
                return;
            }
            
            try {
                // Set auth header
                axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
                
                // Verify token is valid by fetching user data
                const response = await axios.get('/api/auth/user');
                setUser(response.data);
                setIsAuthenticated(true);
            } catch (error) {
                console.error('Authentication failed:', error);
                // Set guest user when authentication fails
                const guestUser = getCurrentUser();
                setUser(guestUser);
                setIsAuthenticated(false);
                logout();
            } finally {
                setLoading(false);
            }
        };
        
        if (!value) {
            checkAuth();
        }
    }, [value]);
    
    // Login function
    const login = async (token, userData) => {
        localStorage.setItem('token', token);
        axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
        setUser(userData);
        setIsAuthenticated(true);
    };
    
    // Logout function
    const logout = () => {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        delete axios.defaults.headers.common['Authorization'];
        
        // Set guest user when logging out
        const guestUser = getCurrentUser();
        setUser(guestUser);
        setIsAuthenticated(false);
    };
    
    return (
        <AuthContext.Provider
            value={{
                isAuthenticated,
                user,
                loading,
                login,
                logout,
                isGuest: user?.isGuest || false
            }}
        >
            {children}
        </AuthContext.Provider>
    );
};

// Custom hook for using the auth context
export const useAuth = () => {
    const context = useContext(AuthContext);
    
    if (!context) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    
    return context;
};

// Helper function to set auth token
export const setAuthToken = (token) => {
    if (token) {
        axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    } else {
        delete axios.defaults.headers.common['Authorization'];
    }
};

export default AuthContext; 