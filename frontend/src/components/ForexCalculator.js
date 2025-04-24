import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Form, Button, Card, Alert, Spinner } from 'react-bootstrap';

const currencies = [
  "USD", "EUR", "GBP", "JPY", "AUD", "CAD", "CHF", "CNY", "NZD"
];

const ForexCalculator = () => {
  const [baseCurrency, setBaseCurrency] = useState('USD');
  const [targetCurrency, setTargetCurrency] = useState('EUR');
  const [basePrice, setBasePrice] = useState('');
  const [convertedPrice, setConvertedPrice] = useState(null);
  const [priceDifferential, setPriceDifferential] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const fetchPriceDifferential = async () => {
    if (!baseCurrency || !targetCurrency) {
      setError('Please select both currencies.');
      return;
    }
    setError('');
    setLoading(true);
    try {
      const response = await axios.get('http://localhost:8000/api/forex-rate', {
        params: {
          base: baseCurrency,
          target: targetCurrency
        }
      });
      const data = response.data;
      setPriceDifferential(data.price_differential);
      if (basePrice !== '') {
        setConvertedPrice((parseFloat(basePrice) * data.price_differential).toFixed(4));
      } else {
        setConvertedPrice(null);
      }
    } catch (err) {
      setError('Failed to fetch price differential.');
      setPriceDifferential(null);
      setConvertedPrice(null);
    }
    setLoading(false);
  };

  useEffect(() => {
    fetchPriceDifferential();
  }, [baseCurrency, targetCurrency]);

  useEffect(() => {
    if (priceDifferential !== null && basePrice !== '') {
      setConvertedPrice((parseFloat(basePrice) * priceDifferential).toFixed(4));
    } else {
      setConvertedPrice(null);
    }
  }, [basePrice, priceDifferential]);

  return (
    <Card className="p-4">
      <h3 className="mb-4">Forex Price Differential Calculator</h3>
      {error && <Alert variant="danger">{error}</Alert>}
      <Form>
        <Form.Group className="mb-3" controlId="baseCurrency">
          <Form.Label>Base Currency</Form.Label>
          <Form.Select value={baseCurrency} onChange={e => setBaseCurrency(e.target.value)}>
            {currencies.map(curr => (
              <option key={curr} value={curr}>{curr}</option>
            ))}
          </Form.Select>
        </Form.Group>

        <Form.Group className="mb-3" controlId="targetCurrency">
          <Form.Label>Target Currency</Form.Label>
          <Form.Select value={targetCurrency} onChange={e => setTargetCurrency(e.target.value)}>
            {currencies.map(curr => (
              <option key={curr} value={curr}>{curr}</option>
            ))}
          </Form.Select>
        </Form.Group>

        <Form.Group className="mb-3" controlId="basePrice">
          <Form.Label>Price in {baseCurrency}</Form.Label>
          <Form.Control
            type="number"
            placeholder={`Enter price in ${baseCurrency}`}
            value={basePrice}
            onChange={e => setBasePrice(e.target.value)}
            min="0"
          />
        </Form.Group>

        <Form.Group className="mb-3">
          <Form.Label>Converted Price in {targetCurrency}</Form.Label>
          <Form.Control
            type="text"
            readOnly
            value={loading ? 'Loading...' : (convertedPrice !== null ? convertedPrice : '')}
          />
        </Form.Group>

        <Form.Group>
          <Form.Label>Price Differential (1 {baseCurrency} = ? {targetCurrency})</Form.Label>
          <Form.Control
            type="text"
            readOnly
            value={loading ? 'Loading...' : (priceDifferential !== null ? priceDifferential.toFixed(4) : '')}
          />
        </Form.Group>
      </Form>
    </Card>
  );
};

export default ForexCalculator;
