import React from 'react';
import { Modal, Table, Badge } from 'react-bootstrap';

const TokenComparison = ({ show, onHide, token1, token2 }) => {
  const decodeToken = (token) => {
    try {
      const [headerB64, payloadB64] = token.split('.');
      return {
        header: JSON.parse(atob(headerB64)),
        payload: JSON.parse(atob(payloadB64))
      };
    } catch (e) {
      return { header: {}, payload: {} };
    }
  };

  const compareObjects = (obj1, obj2) => {
    const allKeys = [...new Set([...Object.keys(obj1), ...Object.keys(obj2)])];
    return allKeys.map(key => ({
      key,
      value1: obj1[key],
      value2: obj2[key],
      different: JSON.stringify(obj1[key]) !== JSON.stringify(obj2[key])
    }));
  };

  const decoded1 = decodeToken(token1?.value || '');
  const decoded2 = decodeToken(token2?.value || '');

  const headerComparison = compareObjects(decoded1.header, decoded2.header);
  const payloadComparison = compareObjects(decoded1.payload, decoded2.payload);

  const renderValue = (value) => {
    if (value === undefined) return <Badge bg="warning">Missing</Badge>;
    return typeof value === 'object' ? 
      <pre className="mb-0">{JSON.stringify(value, null, 2)}</pre> : 
      <code>{String(value)}</code>;
  };

  return (
    <Modal show={show} onHide={onHide} size="lg">
      <Modal.Header closeButton>
        <Modal.Title>Token Comparison</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <h5>Header Comparison</h5>
        <Table responsive striped bordered hover>
          <thead>
            <tr>
              <th>Claim</th>
              <th>Token 1 Value</th>
              <th>Token 2 Value</th>
            </tr>
          </thead>
          <tbody>
            {headerComparison.map(({ key, value1, value2, different }) => (
              <tr key={key} className={different ? 'table-warning' : ''}>
                <td><strong>{key}</strong></td>
                <td>{renderValue(value1)}</td>
                <td>{renderValue(value2)}</td>
              </tr>
            ))}
          </tbody>
        </Table>

        <h5 className="mt-4">Payload Comparison</h5>
        <Table responsive striped bordered hover>
          <thead>
            <tr>
              <th>Claim</th>
              <th>Token 1 Value</th>
              <th>Token 2 Value</th>
            </tr>
          </thead>
          <tbody>
            {payloadComparison.map(({ key, value1, value2, different }) => (
              <tr key={key} className={different ? 'table-warning' : ''}>
                <td><strong>{key}</strong></td>
                <td>{renderValue(value1)}</td>
                <td>{renderValue(value2)}</td>
              </tr>
            ))}
          </tbody>
        </Table>

        <div className="mt-3">
          <small className="text-muted">
            <Badge bg="warning" className="me-2">Highlighted rows</Badge>
            indicate differences between the tokens
          </small>
        </div>
      </Modal.Body>
    </Modal>
  );
};

export default TokenComparison;