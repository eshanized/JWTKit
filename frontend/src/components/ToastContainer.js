import React from 'react';
import Toast from './Toast';
import { useToast } from '../context/ToastContext';

const ToastContainer = () => {
  const { toasts, removeToast } = useToast();
  
  return (
    <div className="toast-container">
      {toasts && toasts.map((toast) => (
        <Toast
          key={toast.id}
          id={toast.id}
          type={toast.type}
          message={toast.message}
          onClose={() => removeToast(toast.id)}
        />
      ))}
    </div>
  );
};

export default ToastContainer;