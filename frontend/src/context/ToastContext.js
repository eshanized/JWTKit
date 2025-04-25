import React, { createContext, useState, useContext } from 'react';

// Create context
const ToastContext = createContext(null);

// Provider component
export const ToastProvider = ({ children }) => {
    const [toasts, setToasts] = useState([]);
    
    const addToast = (message, type = 'info', duration = 5000) => {
        const id = Date.now();
        const newToast = { id, message, type, duration };
        setToasts(prevToasts => [...prevToasts, newToast]);
        
        // Auto-remove after duration
        setTimeout(() => {
            removeToast(id);
        }, duration);
        
        return id;
    };
    
    const removeToast = (id) => {
        setToasts(prevToasts => prevToasts.filter(toast => toast.id !== id));
    };
    
    return (
        <ToastContext.Provider value={{ toasts, addToast, removeToast }}>
            {children}
        </ToastContext.Provider>
    );
};

// Custom hook to use the toast context
export const useToast = () => {
    const context = useContext(ToastContext);
    
    if (!context) {
        throw new Error('useToast must be used within a ToastProvider');
    }
    
    return context;
};

export default ToastContext; 