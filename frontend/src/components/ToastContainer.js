import React, { useContext } from 'react';
import ToastContext from '../context/ToastContext';

const ToastContainer = () => {
  const { toasts, removeToast } = useContext(ToastContext);
  
  return (
    <div className="toast-container">
      {toasts.map(toast => (
        <div key={toast.id} className={`toast toast-${toast.type}`}>
          <div className="toast-content">{toast.message}</div>
          <button className="toast-close" onClick={() => removeToast(toast.id)}>
            &times;
          </button>
        </div>
      ))}
    </div>
  );
};

export default ToastContainer;