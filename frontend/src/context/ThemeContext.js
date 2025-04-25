import React, { createContext, useState, useContext, useEffect } from 'react';

// Create context
const ThemeContext = createContext(null);

// Provider component
export const ThemeProvider = ({ children, value }) => {
    const [theme, setTheme] = useState(value?.theme || 'light');
    
    const toggleTheme = () => {
        const newTheme = theme === 'light' ? 'dark' : 'light';
        setTheme(newTheme);
        localStorage.setItem('theme', newTheme);
        document.documentElement.setAttribute('data-theme', newTheme);
    };
    
    // Initial setup
    useEffect(() => {
        const savedTheme = localStorage.getItem('theme') || 'light';
        setTheme(savedTheme);
        document.documentElement.setAttribute('data-theme', savedTheme);
    }, []);
    
    return (
        <ThemeContext.Provider value={{ theme, toggleTheme }}>
            {children}
        </ThemeContext.Provider>
    );
};

// Custom hook to use the theme context
export const useTheme = () => {
    const context = useContext(ThemeContext);
    
    if (!context) {
        throw new Error('useTheme must be used within a ThemeProvider');
    }
    
    return context;
};

export default ThemeContext; 