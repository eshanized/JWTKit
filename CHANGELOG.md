# Changelog

All notable changes to JWTKit will be documented in this file.

## [Unreleased]

### Added
- Security Pattern Detector component for analyzing security logs
- Key Management API with routes for:
  - Listing, creating, and deleting keys
  - Generating RSA, EC, and HMAC keys
  - Exporting JWKS for verification
- JWT Authentication system with login and registration
- Token analysis and manipulation features
- Attack simulation capabilities
- Vulnerability scanning functionality
- Audit logging system

### Fixed
- Linter errors in `key_management.py` by ensuring proper handling of JSON request data
- Properly handling potential `None` values in request JSON by using fallback empty dictionaries
- Updated Login component with new styles from auth.css

### Changed
- Made all routes public in the frontend by modifying the ProtectedRoute component
- Updated component structure for better organization
- Improved error handling throughout the application

### Removed
- GitLab CI configuration (`.gitlab-ci.yml`) as the project is now deployed via GitHub Pages 