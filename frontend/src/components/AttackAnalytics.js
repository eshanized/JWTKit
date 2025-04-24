import React, { useState, useEffect } from 'react';
import { Card, Row, Col, Form } from 'react-bootstrap';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  ResponsiveContainer, PieChart, Pie, Cell
} from 'recharts';

const AttackAnalytics = () => {
  const [logs, setLogs] = useState([]);
  const [timeRange, setTimeRange] = useState('24h');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchLogs();
  }, [timeRange]);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const endDate = new Date();
      const startDate = new Date();
      
      switch (timeRange) {
        case '24h':
          startDate.setHours(startDate.getHours() - 24);
          break;
        case '7d':
          startDate.setDate(startDate.getDate() - 7);
          break;
        case '30d':
          startDate.setDate(startDate.getDate() - 30);
          break;
        default:
          startDate.setHours(startDate.getHours() - 24);
      }

      const response = await fetch(
        `http://localhost:8000/audit-log?historical=true&start_date=${startDate.toISOString()}&end_date=${endDate.toISOString()}`
      );
      const data = await response.json();
      setLogs(data);
    } catch (err) {
      console.error('Failed to fetch audit logs:', err);
    } finally {
      setLoading(false);
    }
  };

  const getAttackTypeStats = () => {
    const stats = logs.reduce((acc, log) => {
      if (log.action.includes('Attack')) {
        acc[log.action] = (acc[log.action] || 0) + 1;
      }
      return acc;
    }, {});

    return Object.entries(stats).map(([name, value]) => ({
      name: name.replace(' Attack', ''),
      value
    }));
  };

  const getSuccessRateStats = () => {
    const total = logs.length;
    const successful = logs.filter(log => log.success).length;
    return [
      { name: 'Successful', value: successful },
      { name: 'Failed', value: total - successful }
    ];
  };

  const getSeverityStats = () => {
    return logs.reduce((acc, log) => {
      acc[log.severity] = (acc[log.severity] || 0) + 1;
      return acc;
    }, {});
  };

  const getTimeSeriesData = () => {
    const timeData = {};
    logs.forEach(log => {
      const date = new Date(log.timestamp);
      const key = timeRange === '24h' 
        ? `${date.getHours()}:00`
        : date.toLocaleDateString();
      
      timeData[key] = timeData[key] || { time: key, total: 0, successful: 0 };
      timeData[key].total++;
      if (log.success) {
        timeData[key].successful++;
      }
    });

    return Object.values(timeData);
  };

  const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884D8'];

  return (
    <div>
      <Card className="mb-4">
        <Card.Header className="d-flex justify-content-between align-items-center">
          <h5 className="mb-0">Attack Analytics</h5>
          <Form.Select 
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
            style={{ width: 'auto' }}
          >
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
          </Form.Select>
        </Card.Header>
        <Card.Body>
          <Row>
            <Col md={6}>
              <Card className="mb-4">
                <Card.Header>Attack Types Distribution</Card.Header>
                <Card.Body>
                  <div style={{ width: '100%', height: 300 }}>
                    <ResponsiveContainer>
                      <PieChart>
                        <Pie
                          data={getAttackTypeStats()}
                          dataKey="value"
                          nameKey="name"
                          cx="50%"
                          cy="50%"
                          outerRadius={80}
                          fill="#8884d8"
                          label
                        >
                          {getAttackTypeStats().map((entry, index) => (
                            <Cell key={index} fill={COLORS[index % COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip />
                        <Legend />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                </Card.Body>
              </Card>
            </Col>
            <Col md={6}>
              <Card className="mb-4">
                <Card.Header>Success Rate</Card.Header>
                <Card.Body>
                  <div style={{ width: '100%', height: 300 }}>
                    <ResponsiveContainer>
                      <PieChart>
                        <Pie
                          data={getSuccessRateStats()}
                          dataKey="value"
                          nameKey="name"
                          cx="50%"
                          cy="50%"
                          outerRadius={80}
                          fill="#8884d8"
                          label
                        >
                          <Cell fill="#00C49F" />
                          <Cell fill="#FF8042" />
                        </Pie>
                        <Tooltip />
                        <Legend />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                </Card.Body>
              </Card>
            </Col>
          </Row>
          <Row>
            <Col md={12}>
              <Card>
                <Card.Header>Attack Attempts Over Time</Card.Header>
                <Card.Body>
                  <div style={{ width: '100%', height: 300 }}>
                    <ResponsiveContainer>
                      <BarChart
                        data={getTimeSeriesData()}
                        margin={{ top: 20, right: 30, left: 20, bottom: 5 }}
                      >
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="time" />
                        <YAxis />
                        <Tooltip />
                        <Legend />
                        <Bar dataKey="total" fill="#8884d8" name="Total Attempts" />
                        <Bar dataKey="successful" fill="#82ca9d" name="Successful Attempts" />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </Card.Body>
              </Card>
            </Col>
          </Row>
        </Card.Body>
      </Card>
    </div>
  );
};

export default AttackAnalytics;