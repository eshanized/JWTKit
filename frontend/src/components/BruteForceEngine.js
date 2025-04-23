import React, { useState } from 'react';
import { Form, Button, Card, Alert, ProgressBar } from 'react-bootstrap';
import axios from 'axios';

const BruteForceEngine = ({ token }) => {
  const [wordlist, setWordlist] = useState('');
  const [customWords, setCustomWords] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [progress, setProgress] = useState(0);

  // Predefined lists of common secrets
  const commonSecrets = [
    'secret', 'password', 'admin', '123456', 'qwerty', 
    'letmein', 'welcome', 'monkey', 'football', 'baseball',
    '1234567890', 'password123', 'admin123', 'test', 'test123',
    'jwt_secret', 'api_key', 'signing_key', 'auth_secret', 'token_secret',
    'client_secret', 'app_secret', 'api_secret', 'application_secret', 'server_secret',
    'key', 'private_key', 'auth_key', 'jwt_key', 'hmac_key',
    'HS256_secret', 'sharedKey', 'apiSecret', 'jwtSigningKey', 'TOKEN_SECRET'
  ];

  // Predefined wordlists
  const predefinedWordlists = {
    common: commonSecrets,
    web_secrets: [
      'AUTH_SECRET', 'JWT_SECRET', 'SIGNING_KEY', 'ENCRYPTION_KEY', 'API_SECRET',
      'SESSION_SECRET', 'COOKIE_SECRET', 'CSRF_SECRET', 'APP_SECRET', 'TOKEN_KEY',
      'PRIVATE_KEY', 'SECRET_KEY', 'APP_KEY', 'OAUTH_SECRET', 'CLIENT_SECRET'
    ],
    weak_passwords: [
      'password', '123456', 'qwerty', 'admin', 'welcome', 
      'password123', 'admin123', 'letmein', '12345678', 'abc123'
    ],
    environment_vars: [
      'NODE_ENV', 'REACT_APP_SECRET', 'NEXT_PUBLIC_KEY', 'VUE_APP_SECRET', 
      'SECRET', 'API_KEY', 'REACT_APP_API_KEY', 'NEXT_AUTH_SECRET', 'JWT_SECRET_KEY'
    ]
  };

  const [wordlistType, setWordlistType] = useState('common');

  const bruteForce = async () => {
    if (!token.trim()) {
      setError('Please enter a JWT token first');
      return;
    }

    if (!wordlist && !customWords.trim()) {
      setError('Please select a wordlist or enter custom words');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);
    setProgress(0);

    try {
      // Determine which wordlist to use
      let wordArray = [];
      
      if (wordlist === 'custom' && customWords.trim()) {
        wordArray = customWords.split('\n').filter(word => word.trim().length > 0);
      } else if (wordlist in predefinedWordlists) {
        wordArray = predefinedWordlists[wordlist];
      }

      if (wordArray.length === 0) {
        throw new Error('Wordlist is empty');
      }

      // Set up progress tracking
      const totalWords = wordArray.length;
      let wordsChecked = 0;
      
      // Use an actual API call with batching to improve performance
      // Process in batches of 10 to show progress
      const batchSize = 10;
      const batches = Math.ceil(wordArray.length / batchSize);
      
      for (let i = 0; i < batches; i++) {
        const batchWords = wordArray.slice(i * batchSize, (i + 1) * batchSize);
        
        const response = await axios.post('http://localhost:8000/brute-force', {
          token,
          wordlist: batchWords
        });
        
        wordsChecked += batchWords.length;
        setProgress(Math.floor((wordsChecked / totalWords) * 100));
        
        // If a secret was found, stop processing
        if (response.data.success) {
          setResult(response.data);
          setLoading(false);
          return;
        }
      }
      
      // If we've reached here, no password was found
      setResult({
        success: false,
        message: "Secret not found in provided wordlist",
        words_checked: wordsChecked
      });
    } catch (err) {
      setError(`Brute force attempt failed: ${err.response?.data?.error || err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h2>JWT Brute Force Engine</h2>
      <p>Attempt to crack the secret key used for HS256 tokens</p>
      
      {!token && (
        <Alert variant="info">
          Enter a JWT in the decoder tab to attempt to crack its secret
        </Alert>
      )}
      
      <Alert variant="warning">
        <i className="bi bi-exclamation-triangle-fill me-2"></i>
        <strong>Educational Purpose Only:</strong> This tool is for security research and should only be used against your own systems or with explicit permission.
      </Alert>
      
      <Form>
        <Form.Group className="mb-3">
          <Form.Label>Wordlist</Form.Label>
          <Form.Select
            value={wordlist}
            onChange={(e) => setWordlist(e.target.value)}
          >
            <option value="">Select a wordlist</option>
            <option value="common">Common JWT secrets</option>
            <option value="web_secrets">Web Application Secrets</option>
            <option value="weak_passwords">Weak Passwords</option>
            <option value="environment_vars">Environment Variables</option>
            <option value="custom">Custom wordlist</option>
          </Form.Select>
        </Form.Group>
        
        {wordlist === 'custom' && (
          <Form.Group className="mb-3">
            <Form.Label>Custom Wordlist</Form.Label>
            <Form.Control
              as="textarea"
              rows={5}
              value={customWords}
              onChange={(e) => setCustomWords(e.target.value)}
              placeholder="Enter one word per line..."
            />
            <Form.Text className="text-muted">
              Enter potential secrets, one per line
            </Form.Text>
          </Form.Group>
        )}
        
        <Button
          variant="danger"
          onClick={bruteForce}
          disabled={loading || !token.trim() || (!wordlist || (wordlist === 'custom' && !customWords.trim()))}
        >
          {loading ? 'Brute Forcing...' : 'Start Brute Force'}
        </Button>
      </Form>
      
      {error && (
        <Alert variant="danger" className="mt-3">
          {error}
        </Alert>
      )}
      
      {loading && (
        <Card className="mt-4">
          <Card.Header>Brute Force Progress</Card.Header>
          <Card.Body>
            <ProgressBar 
              animated 
              now={progress} 
              label={`${progress}%`} 
            />
            <div className="mt-2 text-center">
              Testing possible secrets... {progress}% complete
            </div>
          </Card.Body>
        </Card>
      )}
      
      {result && (
        <Card className="mt-4">
          <Card.Header className={result.success ? "bg-success text-white" : "bg-warning text-white"}>
            <strong>Brute Force Result</strong>
          </Card.Header>
          <Card.Body>
            {result.success ? (
              <>
                <Alert variant="success">
                  <i className="bi bi-check-circle-fill me-2"></i>
                  {result.message}
                </Alert>
                
                <div className="mt-3">
                  <h5>Secret Found:</h5>
                  <div className="border p-3 bg-light">
                    <code>{result.secret_found}</code>
                  </div>
                </div>
              </>
            ) : (
              <Alert variant="warning">
                <i className="bi bi-exclamation-circle-fill me-2"></i>
                {result.message}
                <div className="mt-2">
                  Words checked: <strong>{result.words_checked}</strong>
                </div>
              </Alert>
            )}
          </Card.Body>
        </Card>
      )}
    </div>
  );
};

export default BruteForceEngine; 