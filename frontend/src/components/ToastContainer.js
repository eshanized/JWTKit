import React from 'react';
import Toast from './Toast';

const ToastContainer = ({ toasts, removeToast }) => {
  return (
    <div className="toast-container">
      {toasts.map((toast) => (
        <Toast
          key={toast.id}
          show={true}
          onClose={() => removeToast(toast.id)}
          variant={toast.variant}
          title={toast.title}
          message={toast.message}
        />
      ))}
    </div>
  );
};

export default ToastContainer;