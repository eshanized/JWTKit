import React from 'react';
import { Toast as BootstrapToast } from 'react-bootstrap';

const Toast = ({ show, onClose, variant, title, message }) => {
  const getIcon = () => {
    switch (variant) {
      case 'success':
        return 'fa-check-circle';
      case 'danger':
        return 'fa-exclamation-circle';
      case 'warning':
        return 'fa-exclamation-triangle';
      case 'info':
      default:
        return 'fa-info-circle';
    }
  };

  return (
    <BootstrapToast 
      show={show} 
      onClose={onClose} 
      delay={3000} 
      autohide
      className={`bg-${variant} text-white`}
    >
      <BootstrapToast.Header closeButton={false} className="border-0">
        <i className={`fas ${getIcon()} me-2`}></i>
        <strong className="me-auto">{title}</strong>
        <button 
          type="button" 
          className="btn-close btn-close-white" 
          onClick={onClose}
          aria-label="Close"
        ></button>
      </BootstrapToast.Header>
      <BootstrapToast.Body>{message}</BootstrapToast.Body>
    </BootstrapToast>
  );
};

export default Toast;