import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';

const ReportGenerator = () => {
    const [reportType, setReportType] = useState('vulnerability');
    const [tokenId, setTokenId] = useState('');
    const [dateRange, setDateRange] = useState('last7days');
    const [customStartDate, setCustomStartDate] = useState('');
    const [customEndDate, setCustomEndDate] = useState('');
    const [includeTokens, setIncludeTokens] = useState(true);
    const [includeAttacks, setIncludeAttacks] = useState(true);
    const [includeKeys, setIncludeKeys] = useState(false);
    const [fileFormat, setFileFormat] = useState('pdf');
    const [isGenerating, setIsGenerating] = useState(false);
    const [previewData, setPreviewData] = useState(null);
    
    const { user } = useAuth();
    const { addToast } = useToast();
    
    const handleSubmit = async (e) => {
        e.preventDefault();
        setIsGenerating(true);
        
        try {
            // Simulate API call for report generation
            await new Promise(resolve => setTimeout(resolve, 1500));
            
            // In a real app, you would use axios to request a report
            // const response = await axios.post('/api/reports/generate', {
            //     reportType,
            //     tokenId: tokenId || undefined,
            //     dateRange,
            //     customStartDate: dateRange === 'custom' ? customStartDate : undefined,
            //     customEndDate: dateRange === 'custom' ? customEndDate : undefined,
            //     includeTokens,
            //     includeAttacks,
            //     includeKeys,
            //     fileFormat
            // });
            
            // Generate sample preview data
            const mockPreviewData = {
                title: getReportTitle(),
                user: user?.username || 'Anonymous',
                dateGenerated: new Date().toLocaleString(),
                summary: {
                    tokensAnalyzed: 24,
                    vulnerabilitiesFound: 12,
                    attacksSimulated: 16,
                    riskScore: 65
                },
                sections: [
                    {
                        title: 'Key Findings',
                        items: [
                            'Multiple tokens with "none" algorithm detected',
                            'Several tokens with weak HMAC secrets',
                            'Token expiration not set in 33% of tokens',
                            'Missing signature verification in client applications'
                        ]
                    },
                    {
                        title: 'Risk Assessment',
                        content: 'Based on the tokens analyzed, your JWT implementation has a moderate to high risk of security vulnerabilities. The use of weak signature algorithms and lack of proper expiration times are the most significant concerns.'
                    }
                ]
            };
            
            setPreviewData(mockPreviewData);
            addToast('Report generated successfully', 'success');
        } catch (error) {
            console.error('Error generating report:', error);
            addToast('Failed to generate report', 'error');
        } finally {
            setIsGenerating(false);
        }
    };
    
    const getReportTitle = () => {
        switch (reportType) {
            case 'vulnerability':
                return 'JWT Vulnerability Assessment Report';
            case 'attack':
                return 'JWT Attack Simulation Report';
            case 'audit':
                return 'JWT Usage Audit Report';
            case 'security':
                return 'JWT Security Posture Report';
            default:
                return 'JWT Analysis Report';
        }
    };
    
    const downloadReport = () => {
        // In a real app, this would download the actual report
        addToast(`Downloading ${fileFormat.toUpperCase()} report...`, 'info');
        
        // Simulate download delay
        setTimeout(() => {
            addToast('Report downloaded successfully', 'success');
        }, 1500);
    };
    
    return (
        <div className="report-generator">
            <div className="report-generator-header">
                <h1>Report Generator</h1>
                <p className="lead">Create comprehensive security reports for your JWT usage</p>
            </div>
            
            <div className="report-content">
                <div className="report-form-container">
                    <h2>Report Configuration</h2>
                    <form onSubmit={handleSubmit}>
                        <div className="form-group">
                            <label htmlFor="reportType">Report Type</label>
                            <select
                                id="reportType"
                                value={reportType}
                                onChange={(e) => setReportType(e.target.value)}
                                disabled={isGenerating}
                            >
                                <option value="vulnerability">Vulnerability Assessment</option>
                                <option value="attack">Attack Simulation Results</option>
                                <option value="audit">Token Usage Audit</option>
                                <option value="security">Security Posture</option>
                            </select>
                        </div>
                        
                        <div className="form-group">
                            <label htmlFor="tokenId">Specific Token (Optional)</label>
                            <input
                                type="text"
                                id="tokenId"
                                placeholder="Leave empty to include all tokens"
                                value={tokenId}
                                onChange={(e) => setTokenId(e.target.value)}
                                disabled={isGenerating}
                            />
                        </div>
                        
                        <div className="form-group">
                            <label htmlFor="dateRange">Date Range</label>
                            <select
                                id="dateRange"
                                value={dateRange}
                                onChange={(e) => setDateRange(e.target.value)}
                                disabled={isGenerating}
                            >
                                <option value="last24h">Last 24 Hours</option>
                                <option value="last7days">Last 7 Days</option>
                                <option value="last30days">Last 30 Days</option>
                                <option value="last90days">Last 90 Days</option>
                                <option value="allTime">All Time</option>
                                <option value="custom">Custom Range</option>
                            </select>
                        </div>
                        
                        {dateRange === 'custom' && (
                            <div className="custom-date-range">
                                <div className="form-group">
                                    <label htmlFor="customStartDate">Start Date</label>
                                    <input
                                        type="date"
                                        id="customStartDate"
                                        value={customStartDate}
                                        onChange={(e) => setCustomStartDate(e.target.value)}
                                        disabled={isGenerating}
                                    />
                                </div>
                                <div className="form-group">
                                    <label htmlFor="customEndDate">End Date</label>
                                    <input
                                        type="date"
                                        id="customEndDate"
                                        value={customEndDate}
                                        onChange={(e) => setCustomEndDate(e.target.value)}
                                        disabled={isGenerating}
                                    />
                                </div>
                            </div>
                        )}
                        
                        <div className="form-section">
                            <h3>Include in Report</h3>
                            <div className="form-check">
                                <input
                                    type="checkbox"
                                    id="includeTokens"
                                    checked={includeTokens}
                                    onChange={(e) => setIncludeTokens(e.target.checked)}
                                    disabled={isGenerating}
                                />
                                <label htmlFor="includeTokens">Token Analysis</label>
                            </div>
                            <div className="form-check">
                                <input
                                    type="checkbox"
                                    id="includeAttacks"
                                    checked={includeAttacks}
                                    onChange={(e) => setIncludeAttacks(e.target.checked)}
                                    disabled={isGenerating}
                                />
                                <label htmlFor="includeAttacks">Attack Simulations</label>
                            </div>
                            <div className="form-check">
                                <input
                                    type="checkbox"
                                    id="includeKeys"
                                    checked={includeKeys}
                                    onChange={(e) => setIncludeKeys(e.target.checked)}
                                    disabled={isGenerating}
                                />
                                <label htmlFor="includeKeys">Key Management</label>
                            </div>
                        </div>
                        
                        <div className="form-group">
                            <label htmlFor="fileFormat">File Format</label>
                            <select
                                id="fileFormat"
                                value={fileFormat}
                                onChange={(e) => setFileFormat(e.target.value)}
                                disabled={isGenerating}
                            >
                                <option value="pdf">PDF</option>
                                <option value="html">HTML</option>
                                <option value="json">JSON</option>
                                <option value="csv">CSV</option>
                            </select>
                        </div>
                        
                        <div className="form-actions">
                            <button
                                type="submit"
                                className="btn btn-primary"
                                disabled={isGenerating}
                            >
                                {isGenerating ? 'Generating...' : 'Generate Report'}
                            </button>
                        </div>
                    </form>
                </div>
                
                <div className="report-preview">
                    <h2>Report Preview</h2>
                    
                    {isGenerating ? (
                        <div className="preview-loading">
                            <div className="spinner"></div>
                            <p>Generating report...</p>
                        </div>
                    ) : previewData ? (
                        <div className="preview-content">
                            <div className="preview-header">
                                <h3>{previewData.title}</h3>
                                <div className="preview-meta">
                                    <p><strong>Generated for:</strong> {previewData.user}</p>
                                    <p><strong>Date:</strong> {previewData.dateGenerated}</p>
                                </div>
                            </div>
                            
                            <div className="preview-summary">
                                <div className="summary-item">
                                    <span className="summary-value">{previewData.summary.tokensAnalyzed}</span>
                                    <span className="summary-label">Tokens Analyzed</span>
                                </div>
                                <div className="summary-item">
                                    <span className="summary-value">{previewData.summary.vulnerabilitiesFound}</span>
                                    <span className="summary-label">Vulnerabilities</span>
                                </div>
                                <div className="summary-item">
                                    <span className="summary-value">{previewData.summary.attacksSimulated}</span>
                                    <span className="summary-label">Attacks Simulated</span>
                                </div>
                                <div className="summary-item">
                                    <span className="summary-value">{previewData.summary.riskScore}</span>
                                    <span className="summary-label">Risk Score</span>
                                </div>
                            </div>
                            
                            {previewData.sections.map((section, index) => (
                                <div className="preview-section" key={index}>
                                    <h4>{section.title}</h4>
                                    {section.items ? (
                                        <ul>
                                            {section.items.map((item, i) => (
                                                <li key={i}>{item}</li>
                                            ))}
                                        </ul>
                                    ) : (
                                        <p>{section.content}</p>
                                    )}
                                </div>
                            ))}
                            
                            <div className="preview-actions">
                                <button
                                    className="btn btn-primary"
                                    onClick={downloadReport}
                                >
                                    Download {fileFormat.toUpperCase()}
                                </button>
                                <button className="btn btn-secondary">
                                    Send by Email
                                </button>
                            </div>
                        </div>
                    ) : (
                        <div className="preview-empty">
                            <p>Generate a report to see a preview</p>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default ReportGenerator; 