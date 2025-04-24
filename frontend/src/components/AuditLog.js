import React, { useState, useEffect } from 'react';
import { Card, Table, Badge, Button, Form, InputGroup } from 'react-bootstrap';
import { saveAs } from 'file-saver';

const AuditLog = () => {
  const [logs, setLogs] = useState([]);
  const [filter, setFilter] = useState('');
  const [sortField, setSortField] = useState('timestamp');
  const [sortDirection, setSortDirection] = useState('desc');

  useEffect(() => {
    fetchLogs();
  }, []);

  const fetchLogs = async () => {
    try {
      const response = await fetch('http://localhost:8000/audit-log');
      const data = await response.json();
      setLogs(data);
    } catch (err) {
      console.error('Failed to fetch audit logs:', err);
    }
  };

  const getSeverityVariant = (severity) => {
    switch (severity.toLowerCase()) {
      case 'high':
        return 'danger';
      case 'medium':
        return 'warning';
      case 'low':
        return 'info';
      default:
        return 'secondary';
    }
  };

  const formatTimestamp = (timestamp) => {
    return new Date(timestamp).toLocaleString();
  };

  const sortLogs = (a, b) => {
    const multiplier = sortDirection === 'asc' ? 1 : -1;
    if (sortField === 'timestamp') {
      return (new Date(a.timestamp) - new Date(b.timestamp)) * multiplier;
    }
    return (a[sortField] > b[sortField] ? 1 : -1) * multiplier;
  };

  const handleSort = (field) => {
    if (field === sortField) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  };

  const filteredLogs = logs
    .filter(log => 
      log.action.toLowerCase().includes(filter.toLowerCase()) ||
      log.details.toLowerCase().includes(filter.toLowerCase()) ||
      log.severity.toLowerCase().includes(filter.toLowerCase())
    )
    .sort(sortLogs);

  const exportLogs = () => {
    const csv = [
      ['Timestamp', 'Action', 'Details', 'Severity', 'Success', 'Token'],
      ...filteredLogs.map(log => [
        formatTimestamp(log.timestamp),
        log.action,
        log.details,
        log.severity,
        log.success ? 'Yes' : 'No',
        log.token
      ])
    ].map(row => row.join(',')).join('\n');

    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    saveAs(blob, `jwt-audit-log-${new Date().toISOString()}.csv`);
  };

  return (
    <Card>
      <Card.Header className="d-flex justify-content-between align-items-center">
        <h5 className="mb-0">Audit Log</h5>
        <Button 
          variant="outline-primary" 
          size="sm"
          onClick={exportLogs}
        >
          <i className="fas fa-download me-1"></i>
          Export CSV
        </Button>
      </Card.Header>
      <Card.Body>
        <InputGroup className="mb-3">
          <InputGroup.Text>
            <i className="fas fa-search"></i>
          </InputGroup.Text>
          <Form.Control
            placeholder="Filter logs..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
        </InputGroup>

        <div className="table-responsive">
          <Table hover bordered>
            <thead>
              <tr>
                <th style={{ cursor: 'pointer' }} onClick={() => handleSort('timestamp')}>
                  Timestamp {sortField === 'timestamp' && (
                    <i className={`fas fa-sort-${sortDirection}`}></i>
                  )}
                </th>
                <th style={{ cursor: 'pointer' }} onClick={() => handleSort('action')}>
                  Action {sortField === 'action' && (
                    <i className={`fas fa-sort-${sortDirection}`}></i>
                  )}
                </th>
                <th>Details</th>
                <th style={{ cursor: 'pointer' }} onClick={() => handleSort('severity')}>
                  Severity {sortField === 'severity' && (
                    <i className={`fas fa-sort-${sortDirection}`}></i>
                  )}
                </th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {filteredLogs.map((log, index) => (
                <tr key={index}>
                  <td className="text-nowrap">{formatTimestamp(log.timestamp)}</td>
                  <td>
                    <Badge bg="secondary" className="text-wrap">
                      {log.action}
                    </Badge>
                  </td>
                  <td>{log.details}</td>
                  <td>
                    <Badge bg={getSeverityVariant(log.severity)}>
                      {log.severity.toUpperCase()}
                    </Badge>
                  </td>
                  <td>
                    <Badge bg={log.success ? 'success' : 'danger'}>
                      {log.success ? 'Success' : 'Failed'}
                    </Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        </div>
      </Card.Body>
    </Card>
  );
};

export default AuditLog;