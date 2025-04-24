import React, { useState, useEffect } from 'react';
import { Card, Table, Badge, Row, Col, Form } from 'react-bootstrap';
import SecurityPatternDetector from './SecurityPatternDetector';
import AttackAnalytics from './AttackAnalytics';

const AuditLog = () => {
  const [logs, setLogs] = useState([]);
  const [filteredLogs, setFilteredLogs] = useState([]);
  const [filters, setFilters] = useState({
    severity: 'all',
    success: 'all',
    timeRange: '24h'
  });

  useEffect(() => {
    fetchLogs();
    // Poll for new logs every 30 seconds
    const interval = setInterval(fetchLogs, 30000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    applyFilters();
  }, [logs, filters]);

  const fetchLogs = async () => {
    try {
      const response = await fetch('http://localhost:8000/audit/logs');
      const data = await response.json();
      setLogs(data);
    } catch (error) {
      console.error('Error fetching audit logs:', error);
    }
  };

  const applyFilters = () => {
    let filtered = [...logs];

    // Apply severity filter
    if (filters.severity !== 'all') {
      filtered = filtered.filter(log => log.severity === filters.severity);
    }

    // Apply success filter
    if (filters.success !== 'all') {
      filtered = filtered.filter(log => log.success === (filters.success === 'true'));
    }

    // Apply time range filter
    const now = new Date();
    const timeRanges = {
      '1h': 60 * 60 * 1000,
      '24h': 24 * 60 * 60 * 1000,
      '7d': 7 * 24 * 60 * 60 * 1000,
      '30d': 30 * 24 * 60 * 60 * 1000
    };

    if (filters.timeRange in timeRanges) {
      const cutoff = now.getTime() - timeRanges[filters.timeRange];
      filtered = filtered.filter(log => new Date(log.timestamp).getTime() > cutoff);
    }

    setFilteredLogs(filtered);
  };

  const getSeverityBadge = (severity) => {
    const variant = severity === 'high' ? 'danger' :
                   severity === 'medium' ? 'warning' : 'info';
    return (
      <Badge bg={variant}>
        {severity.toUpperCase()}
      </Badge>
    );
  };

  return (
    <div>
      <Row className="mb-4">
        <Col>
          <AttackAnalytics logs={filteredLogs} />
        </Col>
      </Row>

      <Row className="mb-4">
        <Col>
          <SecurityPatternDetector logs={filteredLogs} />
        </Col>
      </Row>

      <Card>
        <Card.Header className="d-flex justify-content-between align-items-center">
          <h5 className="mb-0">Audit Log</h5>
          <div className="d-flex gap-3">
            <Form.Select
              size="sm"
              value={filters.severity}
              onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
            >
              <option value="all">All Severities</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </Form.Select>

            <Form.Select
              size="sm"
              value={filters.success}
              onChange={(e) => setFilters({ ...filters, success: e.target.value })}
            >
              <option value="all">All Results</option>
              <option value="true">Success</option>
              <option value="false">Failure</option>
            </Form.Select>

            <Form.Select
              size="sm"
              value={filters.timeRange}
              onChange={(e) => setFilters({ ...filters, timeRange: e.target.value })}
            >
              <option value="1h">Last Hour</option>
              <option value="24h">Last 24 Hours</option>
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
            </Form.Select>
          </div>
        </Card.Header>
        <Card.Body>
          <div className="table-responsive">
            <Table striped bordered hover>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Action</th>
                  <th>IP Address</th>
                  <th>Token</th>
                  <th>Status</th>
                  <th>Severity</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {filteredLogs.map((log, index) => (
                  <tr key={index}>
                    <td>{new Date(log.timestamp).toLocaleString()}</td>
                    <td>{log.action}</td>
                    <td>{log.ip_address}</td>
                    <td>
                      <code className="text-break">{log.token?.substring(0, 20)}...</code>
                    </td>
                    <td>
                      <Badge bg={log.success ? 'success' : 'danger'}>
                        {log.success ? 'Success' : 'Failure'}
                      </Badge>
                    </td>
                    <td>{getSeverityBadge(log.severity)}</td>
                    <td>{log.details}</td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </div>
        </Card.Body>
      </Card>
    </div>
  );
};

export default AuditLog;