import React, { useEffect, useState } from 'react';
import { Card, Row, Col } from 'react-bootstrap';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  PieChart, Pie, Cell
} from 'recharts';

const AttackAnalytics = ({ logs }) => {
  const [attackStats, setAttackStats] = useState({
    byType: [],
    bySeverity: [],
    byTimeOfDay: []
  });

  useEffect(() => {
    analyzeLogs();
  }, [logs]);

  const analyzeLogs = () => {
    const attackTypes = {};
    const severityCount = { high: 0, medium: 0, low: 0 };
    const timeOfDay = Array(24).fill(0);

    logs.forEach(log => {
      // Count attack types
      const type = determineAttackType(log);
      attackTypes[type] = (attackTypes[type] || 0) + 1;

      // Count severities
      severityCount[log.severity] = (severityCount[log.severity] || 0) + 1;

      // Count by hour of day
      const hour = new Date(log.timestamp).getHours();
      timeOfDay[hour]++;
    });

    setAttackStats({
      byType: Object.entries(attackTypes).map(([name, value]) => ({ name, value })),
      bySeverity: Object.entries(severityCount).map(([name, value]) => ({ name, value })),
      byTimeOfDay: timeOfDay.map((value, index) => ({
        hour: index.toString().padStart(2, '0') + ':00',
        attempts: value
      }))
    });
  };

  const determineAttackType = (log) => {
    if (!log.token) return 'Unknown';
    
    if (log.token.includes('"alg":"none"') || log.token.includes('"alg":null')) {
      return 'Algorithm Confusion';
    }
    if (log.token.split('.').length < 3) {
      return 'Signature Stripping';
    }
    if (log.token.includes('"admin":true') || log.token.includes('"role":"admin"')) {
      return 'Privilege Escalation';
    }
    return 'Other';
  };

  const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884d8'];

  return (
    <Card>
      <Card.Header>
        <h5 className="mb-0">Attack Analytics</h5>
      </Card.Header>
      <Card.Body>
        <Row>
          <Col md={4}>
            <h6 className="text-center">Attack Types Distribution</h6>
            <PieChart width={300} height={300}>
              <Pie
                data={attackStats.byType}
                cx={150}
                cy={150}
                labelLine={false}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
              >
                {attackStats.byType.map((entry, index) => (
                  <Cell key={index} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </Col>

          <Col md={4}>
            <h6 className="text-center">Severity Distribution</h6>
            <PieChart width={300} height={300}>
              <Pie
                data={attackStats.bySeverity}
                cx={150}
                cy={150}
                labelLine={false}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
              >
                {attackStats.bySeverity.map((entry, index) => (
                  <Cell 
                    key={index} 
                    fill={entry.name === 'high' ? '#dc3545' : 
                          entry.name === 'medium' ? '#ffc107' : '#17a2b8'} 
                  />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </Col>

          <Col md={4}>
            <h6 className="text-center">Attack Attempts by Time of Day</h6>
            <BarChart
              width={400}
              height={300}
              data={attackStats.byTimeOfDay}
              margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
            >
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="hour" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Bar dataKey="attempts" fill="#8884d8" />
            </BarChart>
          </Col>
        </Row>
      </Card.Body>
    </Card>
  );
};

export default AttackAnalytics;