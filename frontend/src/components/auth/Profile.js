import React, { useState, useEffect } from 'react';
import { useAuth } from '../../context/AuthContext';
import axios from 'axios';

const Profile = () => {
    const { user } = useAuth();
    const [stats, setStats] = useState({
        tokens: 0,
        keys: 0,
        reports: 0
    });
    const [loading, setLoading] = useState(true);
    
    useEffect(() => {
        const fetchUserStats = async () => {
            try {
                const response = await axios.get('/api/user/stats');
                setStats(response.data);
            } catch (error) {
                console.error('Error fetching user stats:', error);
                // Use fallback data if API call fails
                setStats({
                    tokens: 12,
                    keys: 5,
                    reports: 3
                });
            } finally {
                setLoading(false);
            }
        };
        
        fetchUserStats();
    }, []);
    
    return (
        <div className="profile-container">
            <div className="profile-header">
                <h1>Your Profile</h1>
                <p className="lead">Manage your account and view your activities</p>
            </div>
            
            <div className="profile-card">
                <div className="profile-info">
                    <h2>{user?.username || 'User'}</h2>
                    <p className="profile-email">{user?.email || 'No email provided'}</p>
                    <p className="profile-role">Role: {user?.role || 'User'}</p>
                </div>
                
                {loading ? (
                    <div className="loading-spinner">
                        <div className="spinner"></div>
                        <p>Loading your data...</p>
                    </div>
                ) : (
                    <div className="stats-grid">
                        <div className="stat-item">
                            <h3>Saved Tokens</h3>
                            <div className="stat-value">{stats.tokens}</div>
                        </div>
                        <div className="stat-item">
                            <h3>Your Keys</h3>
                            <div className="stat-value">{stats.keys}</div>
                        </div>
                        <div className="stat-item">
                            <h3>Reports</h3>
                            <div className="stat-value">{stats.reports}</div>
                        </div>
                    </div>
                )}
                
                <div className="profile-actions">
                    <button className="btn btn-primary">Edit Profile</button>
                    <button className="btn btn-secondary">Change Password</button>
                </div>
            </div>
            
            <div className="recent-activity">
                <h2>Recent Activity</h2>
                <div className="activity-list">
                    <div className="activity-item">
                        <span className="activity-time">Today at 10:45 AM</span>
                        <span className="activity-type">Generated RSA key</span>
                    </div>
                    <div className="activity-item">
                        <span className="activity-time">Yesterday at 3:22 PM</span>
                        <span className="activity-type">Saved new token</span>
                    </div>
                    <div className="activity-item">
                        <span className="activity-time">April 20, 2025 at 9:15 AM</span>
                        <span className="activity-type">Ran attack simulation</span>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Profile; 