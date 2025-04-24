import React, { useState } from 'react';
import { Card, Table, Button, Badge, Modal } from 'react-bootstrap';
import TokenComparison from './TokenComparison';

const TokenHistory = ({ tokens = [], onSelectToken, onCompare }) => {
  const [showCompareModal, setShowCompareModal] = useState(false);
  const [selectedTokens, setSelectedTokens] = useState([]);
  const [compareTokens, setCompareTokens] = useState({ token1: null, token2: null });

  const handleTokenSelect = (token) => {
    if (selectedTokens.includes(token)) {
      setSelectedTokens(selectedTokens.filter(t => t !== token));
    } else if (selectedTokens.length < 2) {
      setSelectedTokens([...selectedTokens, token]);
    }
  };

  const handleCompare = () => {
    if (selectedTokens.length === 2) {
      setCompareTokens({
        token1: selectedTokens[0],
        token2: selectedTokens[1]
      });
      setShowCompareModal(true);
      onCompare(selectedTokens[0], selectedTokens[1]);
    }
  };

  const formatTimestamp = (timestamp) => {
    return new Date(timestamp).toLocaleString();
  };

  return (
    <>
      <Card className="mb-4">
        <Card.Header className="d-flex justify-content-between align-items-center">
          <h5 className="mb-0">Token History</h5>
          <Button 
            variant="primary" 
            size="sm"
            disabled={selectedTokens.length !== 2}
            onClick={handleCompare}
          >
            Compare Selected
          </Button>
        </Card.Header>
        <Card.Body>
          <Table responsive hover>
            <thead>
              <tr>
                <th></th>
                <th>Token</th>
                <th>Operation</th>
                <th>Timestamp</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {tokens.map((token, index) => (
                <tr key={index}>
                  <td>
                    <input
                      type="checkbox"
                      checked={selectedTokens.includes(token)}
                      onChange={() => handleTokenSelect(token)}
                      disabled={selectedTokens.length === 2 && !selectedTokens.includes(token)}
                    />
                  </td>
                  <td>
                    <code className="text-break">
                      {token.value.substring(0, 20)}...
                    </code>
                  </td>
                  <td>
                    <Badge bg={token.operation === 'original' ? 'primary' : 'info'}>
                      {token.operation}
                    </Badge>
                  </td>
                  <td>{formatTimestamp(token.timestamp)}</td>
                  <td>
                    <Badge bg={token.status === 'valid' ? 'success' : 'danger'}>
                      {token.status}
                    </Badge>
                  </td>
                  <td>
                    <Button
                      variant="outline-secondary"
                      size="sm"
                      onClick={() => onSelectToken(token)}
                    >
                      Load
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Card.Body>
      </Card>

      <TokenComparison
        show={showCompareModal}
        onHide={() => setShowCompareModal(false)}
        token1={compareTokens.token1}
        token2={compareTokens.token2}
      />
    </>
  );
};

export default TokenHistory;