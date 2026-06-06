import React, { useState, useEffect } from 'react';
import { 
  Shield, Users, Key, Settings, Activity, Laptop, 
  RefreshCw, Plus, Trash2, Copy, Check, Info, 
  AlertTriangle, ShieldCheck, FileText, ChevronRight,
  Sliders, HardDrive, ShieldAlert, Award
} from 'lucide-react';

const API_BASE = 'http://localhost:8080/api/v1';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [agents, setAgents] = useState([]);
  const [events, setEvents] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [refreshInterval] = useState(3000); // Poll every 3 seconds

  // Selected Agent Details Modal State
  const [selectedAgentForModal, setSelectedAgentForModal] = useState(null);
  const [appSearchQuery, setAppSearchQuery] = useState('');

  // Setup Token State
  const [tokenWorkgroup, setTokenWorkgroup] = useState('WORKGROUP');
  const [tokenDuration, setTokenDuration] = useState(120);
  const [generatedToken, setGeneratedToken] = useState(null);
  const [copiedToken, setCopiedToken] = useState(false);

  // Policy Editor State
  const [selectedWorkgroup, setSelectedWorkgroup] = useState('WORKGROUP');
  const [policyVersion, setPolicyVersion] = useState(1);
  const [policyId, setPolicyId] = useState('');
  
  // Policy features state
  const [usbEnabled, setUsbEnabled] = useState(true);
  const [usbBlockStorage, setUsbBlockStorage] = useState(true);
  const [usbReadOnly, setUsbReadOnly] = useState(false);

  const [srpEnabled, setSrpEnabled] = useState(true);
  const [srpDefaultLevel, setSrpDefaultLevel] = useState('unrestricted');
  const [srpRules, setSrpRules] = useState([
    { id: 'rule-1', type: 'path', value: '%OSDrive%\\Temp\\*.exe', action: 'disallow', description: 'Block temp binaries' },
    { id: 'rule-2', type: 'path', value: '%UserProfile%\\Downloads\\*.exe', action: 'disallow', description: 'Block downloads execution' }
  ]);
  const [newSrpType, setNewSrpType] = useState('path');
  const [newSrpValue, setNewSrpValue] = useState('');
  const [newSrpDesc, setNewSrpDesc] = useState('');

  const [fwEnabled, setFwEnabled] = useState(true);
  const [fwGlobalState, setFwGlobalState] = useState(true);
  const [fwRules, setFwRules] = useState([
    { name: 'Block_SMB_In', direction: 'in', action: 'block', protocol: 'TCP', local_port: '445', remote_ip: 'any' },
    { name: 'Allow_RDP_Safe', direction: 'in', action: 'allow', protocol: 'TCP', local_port: '3389', remote_ip: '192.168.1.0/24' }
  ]);
  const [newFwName, setNewFwName] = useState('');
  const [newFwDir, setNewFwDir] = useState('in');
  const [newFwAction, setNewFwAction] = useState('allow');
  const [newFwProto, setNewFwProto] = useState('TCP');
  const [newFwPort, setNewFwPort] = useState('any');
  const [newFwIp, setNewFwIp] = useState('any');

  const [accEnabled, setAccEnabled] = useState(true);
  const [accComplexity, setAccComplexity] = useState(true);
  const [accMinLength, setAccMinLength] = useState(12);
  const [accMaxAge, setAccMaxAge] = useState(90);
  const [accMinAge, setAccMinAge] = useState(1);
  const [accThreshold, setAccThreshold] = useState(5);
  const [accDuration, setAccDuration] = useState(30);
  const [accReset, setAccReset] = useState(30);

  const [wuEnabled, setWuEnabled] = useState(true);
  const [wuOption, setWuOption] = useState(4);
  const [wuDay, setWuDay] = useState(0);
  const [wuHour, setWuHour] = useState(3);
  const [wuDeferFeatures, setWuDeferFeatures] = useState(180);
  const [wuDeferQuality, setWuDeferQuality] = useState(7);

  // Notification Toast
  const [notification, setNotification] = useState(null);

  // Fetch agents and events from Go backend
  const fetchData = async () => {
    try {
      const agentsRes = await fetch(`${API_BASE}/agents`);
      if (agentsRes.ok) {
        const data = await agentsRes.json();
        setAgents(data || []);
      }

      const eventsRes = await fetch(`${API_BASE}/events`);
      if (eventsRes.ok) {
        const data = await eventsRes.json();
        setEvents(data || []);
      }
    } catch (error) {
      console.error('API Poll error:', error);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, refreshInterval);
    return () => clearInterval(interval);
  }, []);

  // Fetch latest policy configuration for a selected workgroup
  const loadPolicy = async (wg) => {
    setIsLoading(true);
    try {
      const res = await fetch(`${API_BASE}/policies/latest?workgroup=${wg}`);
      if (res.ok) {
        const data = await res.json();
        if (data && data.policy_id) {
          setPolicyId(data.policy_id);
          setPolicyVersion(data.version);
          
          const feats = data.features || {};
          // USB
          setUsbEnabled(feats.usb_blocking?.enabled ?? false);
          setUsbBlockStorage(feats.usb_blocking?.block_all_mass_storage ?? false);
          setUsbReadOnly(feats.usb_blocking?.allow_read_only_exceptions ?? false);
          // SRP
          setSrpEnabled(feats.software_restriction?.enabled ?? false);
          setSrpDefaultLevel(feats.software_restriction?.default_level ?? 'unrestricted');
          setSrpRules(feats.software_restriction?.rules || []);
          // FW
          setFwEnabled(feats.firewall_orchestration?.enabled ?? false);
          setFwGlobalState(feats.firewall_orchestration?.global_state_on ?? false);
          setFwRules(feats.firewall_orchestration?.rules || []);
          // Account
          setAccEnabled(feats.account_security?.enabled ?? false);
          setAccComplexity(feats.account_security?.password_complexity ?? false);
          setAccMinLength(feats.account_security?.min_password_length ?? 12);
          setAccMaxAge(feats.account_security?.max_password_age_days ?? 90);
          setAccMinAge(feats.account_security?.min_password_age_days ?? 1);
          setAccThreshold(feats.account_security?.lockout_threshold ?? 5);
          setAccDuration(feats.account_security?.lockout_duration_mins ?? 30);
          setAccReset(feats.account_security?.reset_lockout_counter_mins ?? 30);
          // WU
          setWuEnabled(feats.windows_update?.enabled ?? false);
          setWuOption(feats.windows_update?.auto_update_option ?? 4);
          setWuDay(feats.windows_update?.scheduled_install_day ?? 0);
          setWuHour(feats.windows_update?.scheduled_install_hour ?? 3);
          setWuDeferFeatures(feats.windows_update?.defer_feature_updates_days ?? 180);
          setWuDeferQuality(feats.windows_update?.defer_quality_updates_days ?? 7);

          showNotice('success', `Loaded config v${data.version} for ${wg}`);
        } else {
          setPolicyId('');
          setPolicyVersion(1);
          showNotice('info', `Using default template configs for ${wg}`);
        }
      }
    } catch (error) {
      showNotice('error', 'Failed to retrieve policy.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadPolicy(selectedWorkgroup);
  }, [selectedWorkgroup]);

  // Generate Setup Token
  const generateToken = async () => {
    try {
      const res = await fetch(`${API_BASE}/tokens`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          workgroup: tokenWorkgroup,
          duration_minutes: parseInt(tokenDuration)
        })
      });
      if (res.ok) {
        const data = await res.json();
        setGeneratedToken(data);
        showNotice('success', `Token generated for workgroup ${tokenWorkgroup}`);
      } else {
        showNotice('error', 'Failed to create token.');
      }
    } catch (e) {
      showNotice('error', 'Network failure.');
    }
  };

  // Deploy Policy
  const deployPolicy = async () => {
    const nextVersion = policyVersion + 1;
    const envelope = {
      policy_id: `pol-${Math.random().toString(36).substr(2, 9)}`,
      version: nextVersion,
      workgroup: selectedWorkgroup,
      timestamp: new Date().toISOString(),
      features: {
        usb_blocking: {
          enabled: usbEnabled,
          block_all_mass_storage: usbBlockStorage,
          allow_read_only_exceptions: usbReadOnly
        },
        software_restriction: {
          enabled: srpEnabled,
          default_level: srpDefaultLevel,
          rules: srpRules
        },
        firewall_orchestration: {
          enabled: fwEnabled,
          global_state_on: fwGlobalState,
          block_unmanaged_allowances: true,
          rules: fwRules
        },
        account_security: {
          enabled: accEnabled,
          password_complexity: accComplexity,
          min_password_length: parseInt(accMinLength),
          max_password_age_days: parseInt(accMaxAge),
          min_password_age_days: parseInt(accMinAge),
          lockout_threshold: parseInt(accThreshold),
          lockout_duration_mins: parseInt(accDuration),
          reset_lockout_counter_mins: parseInt(accReset)
        },
        windows_update: {
          enabled: wuEnabled,
          auto_update_option: parseInt(wuOption),
          scheduled_install_day: parseInt(wuDay),
          scheduled_install_hour: parseInt(wuHour),
          defer_feature_updates_days: parseInt(wuDeferFeatures),
          defer_quality_updates_days: parseInt(wuDeferQuality)
        }
      }
    };

    try {
      const res = await fetch(`${API_BASE}/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(envelope)
      });
      if (res.ok) {
        const result = await res.json();
        setPolicyVersion(nextVersion);
        setPolicyId(envelope.policy_id);
        showNotice('success', `Policy version ${nextVersion} pushed to ${result.broadcast_count} active agent(s).`);
      } else {
        showNotice('error', 'Failed to deploy policy.');
      }
    } catch (e) {
      showNotice('error', 'Network error.');
    }
  };

  const showNotice = (type, text) => {
    setNotification({ type, text });
    setTimeout(() => setNotification(null), 5000);
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedToken(true);
    setTimeout(() => setCopiedToken(false), 2000);
  };

  // Rule additions
  const addSrpRule = () => {
    if (!newSrpValue) return;
    const exists = srpRules.some(r => r.value.toLowerCase() === newSrpValue.toLowerCase());
    if (exists) {
      showNotice('info', `Software restriction rule for "${newSrpValue}" already exists.`);
      return;
    }
    const rule = {
      id: `rule-${Math.random().toString(36).substr(2, 5)}`,
      type: newSrpType,
      value: newSrpValue,
      action: 'disallow',
      hash_alg: 'sha256',
      file_size_bytes: 0,
      description: newSrpDesc || 'Manually added restriction'
    };
    setSrpRules([...srpRules, rule]);
    setNewSrpValue('');
    setNewSrpDesc('');
  };

  const addFwRule = () => {
    if (!newFwName) return;
    const exists = fwRules.some(r => r.name.toLowerCase() === newFwName.toLowerCase());
    if (exists) {
      showNotice('info', `Firewall rule named "${newFwName}" already exists.`);
      return;
    }
    const rule = {
      name: newFwName,
      direction: newFwDir,
      action: newFwAction,
      protocol: newFwProto,
      local_port: newFwPort,
      remote_port: 'any',
      remote_ip: newFwIp
    };
    setFwRules([...fwRules, rule]);
    setNewFwName('');
  };

  const onlineAgents = agents.filter(a => a.status === 'online').length;
  const uniqueWorkgroups = [...new Set(agents.map(a => a.workgroup))].length;
  const totalHeals = events.filter(e => e.event_type === 'HEAL_ACTION').length;

  return (
    <div className="app-container">
      {/* Toast Notification */}
      {notification && (
        <div 
          style={{
            position: 'fixed',
            top: '24px',
            right: '24px',
            zIndex: 9999,
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            padding: '16px 20px',
            borderRadius: '8px',
            background: '#111827',
            border: `1px solid ${notification.type === 'success' ? '#10b981' : notification.type === 'error' ? '#ef4444' : '#6366f1'}`,
            boxShadow: '0 10px 30px rgba(0,0,0,0.5)',
          }}
        >
          {notification.type === 'success' ? (
            <ShieldCheck style={{ color: 'var(--status-online)' }} size={18} />
          ) : notification.type === 'error' ? (
            <AlertTriangle style={{ color: 'var(--status-offline)' }} size={18} />
          ) : (
            <Info style={{ color: 'var(--color-cyan)' }} size={18} />
          )}
          <span style={{ fontSize: '13px', fontWeight: 500 }}>{notification.text}</span>
        </div>
      )}

      {/* Persistent Left Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-logo">
          <Shield style={{ color: 'var(--color-primary)' }} size={24} />
          <span className="sidebar-logo-text">SHIELD WWPO</span>
        </div>

        <nav className="sidebar-menu">
          <button 
            className={`sidebar-item ${activeTab === 'dashboard' ? 'active' : ''}`}
            onClick={() => setActiveTab('dashboard')}
          >
            <Activity size={16} /> Overview
          </button>
          <button 
            className={`sidebar-item ${activeTab === 'policies' ? 'active' : ''}`}
            onClick={() => setActiveTab('policies')}
          >
            <Settings size={16} /> Policy Manager
          </button>
          <button 
            className={`sidebar-item ${activeTab === 'agents' ? 'active' : ''}`}
            onClick={() => setActiveTab('agents')}
          >
            <Laptop size={16} /> Enrolled Agents
          </button>
          <button 
            className={`sidebar-item ${activeTab === 'tokens' ? 'active' : ''}`}
            onClick={() => setActiveTab('tokens')}
          >
            <Key size={16} /> Setup Tokens
          </button>
        </nav>

        <div style={{ marginTop: 'auto', borderTop: '1px solid var(--border-color)', paddingTop: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span className="status-indicator status-indicator-online"></span>
            <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>Live Server Mode</span>
          </div>
          <span style={{ fontSize: '10px', color: 'var(--text-muted)', display: 'block', marginTop: '6px' }}>API: http://localhost:8080</span>
        </div>
      </aside>

      {/* Main Container Area */}
      <main className="main-content">
        
        {/* Header Row */}
        <header className="header-row">
          <div className="header-title">
            <h1 style={{ textTransform: 'capitalize' }}>{activeTab} Management</h1>
            <p>Windows Decentralized Workgroup Security Controller</p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <button onClick={fetchData} className="btn btn-secondary" title="Sync dashboard data">
              <RefreshCw size={14} /> Refresh
            </button>
            <span className="badge badge-online">
              <span className="status-indicator status-indicator-online" style={{ width: '6px', height: '6px', marginRight: '0' }}></span> Connected
            </span>
          </div>
        </header>

        {/* TAB 1: Dashboard Overview */}
        {activeTab === 'dashboard' && (
          <>
            {/* Top Stats Metrics row */}
            <div className="stats-grid">
              <div className="stat-card">
                <div>
                  <span className="stat-label">Online / Registered</span>
                  <div className="stat-value">{onlineAgents} / {agents.length}</div>
                </div>
                <div className="stat-icon-wrapper" style={{ borderColor: 'rgba(16, 185, 129, 0.2)', background: 'rgba(16, 185, 129, 0.05)' }}>
                  <Laptop style={{ color: 'var(--status-online)' }} size={24} />
                </div>
              </div>

              <div className="stat-card">
                <div>
                  <span className="stat-label">Logical Domains</span>
                  <div className="stat-value" style={{ color: 'var(--color-cyan)' }}>{uniqueWorkgroups || 1}</div>
                </div>
                <div className="stat-icon-wrapper" style={{ borderColor: 'rgba(6, 182, 212, 0.2)', background: 'rgba(6, 182, 212, 0.05)' }}>
                  <Users style={{ color: 'var(--color-cyan)' }} size={24} />
                </div>
              </div>

              <div className="stat-card">
                <div>
                  <span className="stat-label">Incidents Resolved</span>
                  <div className="stat-value" style={{ color: 'var(--color-secondary)' }}>{totalHeals}</div>
                </div>
                <div className="stat-icon-wrapper" style={{ borderColor: 'rgba(168, 85, 247, 0.2)', background: 'rgba(168, 85, 247, 0.05)' }}>
                  <ShieldCheck style={{ color: 'var(--color-secondary)' }} size={24} />
                </div>
              </div>
            </div>

            {/* Split layout: logs terminal and guides */}
            <div className="dashboard-grid">
              {/* Terminal Logs panel */}
              <div className="glass-panel">
                <div className="panel-header">
                  <div className="panel-title">
                    <Activity style={{ color: 'var(--color-primary)' }} size={16} /> Live Security Log Feed
                  </div>
                  <span style={{ fontSize: '11px', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>Auto poll: 3s</span>
                </div>

                <div className="logs-terminal">
                  {events.length === 0 ? (
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: '12px', color: 'var(--text-muted)' }}>
                      <Shield style={{ opacity: 0.15 }} size={48} />
                      <p style={{ fontSize: '13px' }}>No policy violations identified. Active hosts are compliant.</p>
                    </div>
                  ) : (
                    events.map(event => (
                      <div key={event.event_id} className="log-item">
                        <div style={{ marginTop: '2px' }}>
                          {event.event_type === 'HEAL_ACTION' ? (
                            <ShieldCheck style={{ color: 'var(--status-online)' }} size={15} />
                          ) : event.event_type === 'WARNING' || event.event_type === 'ALERT' ? (
                            <ShieldAlert style={{ color: 'var(--status-offline)' }} size={15} />
                          ) : (
                            <Info style={{ color: 'var(--color-primary)' }} size={15} />
                          )}
                        </div>
                        <div style={{ flex: 1 }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                            <span className="log-host">
                              {agents.find(a => a.agent_id === event.agent_id)?.hostname || event.agent_id.substring(0, 8)}
                            </span>
                            <span className="log-timestamp">{new Date(event.timestamp).toLocaleTimeString()}</span>
                          </div>
                          <p className="log-message">{event.message}</p>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* Guidelines panel */}
              <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                <div className="panel-header">
                  <div className="panel-title">
                    <Sliders style={{ color: 'var(--color-cyan)' }} size={16} /> Configuration Guidelines
                  </div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  <div style={{ display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
                    <div style={{ padding: '6px', background: 'rgba(255,255,255,0.05)', borderRadius: '6px' }}>
                      <Key size={14} style={{ color: 'var(--color-cyan)' }} />
                    </div>
                    <div>
                      <h4 style={{ fontSize: '13px', fontWeight: 600, marginBottom: '2px' }}>Enrollment handshakes</h4>
                      <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
                        Generate logical setup keys in the Setup Tokens panel to register new nodes.
                      </p>
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
                    <div style={{ padding: '6px', background: 'rgba(255,255,255,0.05)', borderRadius: '6px' }}>
                      <Settings size={14} style={{ color: 'var(--color-primary)' }} />
                    </div>
                    <div>
                      <h4 style={{ fontSize: '13px', fontWeight: 600, marginBottom: '2px' }}>Decentralized Policies</h4>
                      <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
                        Create security configurations for target domains. Dropped policies won't infect other workgroup systems.
                      </p>
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
                    <div style={{ padding: '6px', background: 'rgba(255,255,255,0.05)', borderRadius: '6px' }}>
                      <Award size={14} style={{ color: 'var(--color-secondary)' }} />
                    </div>
                    <div>
                      <h4 style={{ fontSize: '13px', fontWeight: 600, marginBottom: '2px' }}>Baseline Auditing</h4>
                      <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
                        Active Go agents check rules every 60 seconds and auto-heal manual registry/policy overrides.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </>
        )}

        {/* TAB 2: Policy Manager */}
        {activeTab === 'policies' && (
          <div className="dashboard-grid" style={{ gridTemplateColumns: '1fr 2.2fr' }}>
            {/* Sidebar parameter choice */}
            <div className="glass-panel" style={{ height: 'fit-content', display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <span className="stat-label">Select Target Workgroup</span>
                <select 
                  value={selectedWorkgroup} 
                  onChange={(e) => setSelectedWorkgroup(e.target.value)}
                  style={{ background: 'rgba(0,0,0,0.35)', border: '1px solid var(--border-color)', padding: '10px' }}
                >
                  <option value="WORKGROUP">WORKGROUP</option>
                  <option value="FINANCE_DEPT">FINANCE_DEPT</option>
                  <option value="DEVELOPERS">DEVELOPERS</option>
                  <option value="EXECUTIVE">EXECUTIVE</option>
                </select>
              </div>

              <div style={{ background: 'rgba(0,0,0,0.2)', border: '1px solid var(--border-color)', padding: '14px', borderRadius: '8px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>Status:</span>
                  <span style={{ color: 'var(--status-online)', fontWeight: 600 }}>Active baseline</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>Active Version:</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}>v{policyVersion}</span>
                </div>
              </div>

              <button onClick={deployPolicy} disabled={isLoading} className="btn btn-primary" style={{ width: '100%' }}>
                <ShieldCheck size={16} /> Deploy & Push Policy
              </button>
            </div>

            {/* Feature configuration editors */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              
              {/* Feature: USB blocking */}
              <div className="glass-panel">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                  <div>
                    <h3 style={{ fontSize: '15px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <HardDrive size={16} style={{ color: 'var(--color-primary)' }} /> USB Storage Access Policies
                    </h3>
                  </div>
                  <label className="toggle-switch">
                    <input type="checkbox" checked={usbEnabled} onChange={(e) => setUsbEnabled(e.target.checked)} />
                    <span className="toggle-slider"></span>
                  </label>
                </div>

                {usbEnabled && (
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                    <label style={{ display: 'flex', gap: '12px', background: 'rgba(0,0,0,0.2)', padding: '12px', border: '1px solid var(--border-color)', borderRadius: '8px', cursor: 'pointer' }}>
                      <input type="checkbox" checked={usbBlockStorage} onChange={(e) => setUsbBlockStorage(e.target.checked)} style={{ width: 'auto', marginTop: '3px' }} />
                      <div>
                        <span style={{ fontSize: '13px', fontWeight: 600, display: 'block' }}>Block Mass Storage</span>
                        <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Disable default USBSTOR drivers</span>
                      </div>
                    </label>

                    <label style={{ display: 'flex', gap: '12px', background: 'rgba(0,0,0,0.2)', padding: '12px', border: '1px solid var(--border-color)', borderRadius: '8px', cursor: 'pointer' }}>
                      <input type="checkbox" checked={usbReadOnly} disabled={!usbBlockStorage} onChange={(e) => setUsbReadOnly(e.target.checked)} style={{ width: 'auto', marginTop: '3px' }} />
                      <div>
                        <span style={{ fontSize: '13px', fontWeight: 600, display: 'block' }}>Allow Read-Only exceptions</span>
                        <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Revoke write access parameters only</span>
                      </div>
                    </label>
                  </div>
                )}
              </div>

              {/* Feature: SRP restriction rules */}
              <div className="glass-panel">
                <div style={{ display: 'flex', justifyBetween: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                  <h3 style={{ fontSize: '15px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <ShieldAlert size={16} style={{ color: 'var(--color-secondary)' }} /> Software Restriction Rules (Safer)
                  </h3>
                  <label className="toggle-switch">
                    <input type="checkbox" checked={srpEnabled} onChange={(e) => setSrpEnabled(e.target.checked)} />
                    <span className="toggle-slider"></span>
                  </label>
                </div>

                {srpEnabled && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px', background: 'rgba(0,0,0,0.2)', padding: '10px', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
                      <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>Default Security Level:</span>
                      <select value={srpDefaultLevel} onChange={(e) => setSrpDefaultLevel(e.target.value)} style={{ width: 'auto', padding: '4px 8px' }}>
                        <option value="unrestricted">Unrestricted (Block rules only)</option>
                        <option value="disallowed">Disallowed (Strict Whitelisting)</option>
                      </select>
                    </div>

                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Type</th>
                          <th>Pattern Value</th>
                          <th>Description</th>
                          <th style={{ textAlign: 'right' }}>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {srpRules.map(rule => (
                          <tr key={rule.id}>
                            <td><span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', background: 'rgba(255,255,255,0.06)', padding: '2px 6px', borderRadius: '4px' }}>{rule.type}</span></td>
                            <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-cyan)' }}>{rule.value}</td>
                            <td>{rule.description}</td>
                            <td style={{ textAlign: 'right' }}>
                              <button onClick={() => setSrpRules(srpRules.filter(r => r.id !== rule.id))} style={{ background: 'transparent', color: 'var(--status-offline)' }} title="Remove rule">
                                <Trash2 size={13} />
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>

                    <div style={{ display: 'flex', gap: '10px', background: 'rgba(0,0,0,0.2)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border-color)', alignItems: 'flex-end' }}>
                      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '4px' }}>
                        <span style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>Rule Type</span>
                        <select value={newSrpType} onChange={(e) => setNewSrpType(e.target.value)} style={{ padding: '6px' }}>
                          <option value="path">Path Rule</option>
                          <option value="hash">Hash Rule (SHA256)</option>
                        </select>
                      </div>
                      <div style={{ flex: 2, display: 'flex', flexDirection: 'column', gap: '4px' }}>
                        <span style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>Value</span>
                        <input type="text" value={newSrpValue} onChange={(e) => setNewSrpValue(e.target.value)} placeholder="%AppData%\\*.exe" style={{ padding: '6px' }} />
                      </div>
                      <div style={{ flex: 2, display: 'flex', flexDirection: 'column', gap: '4px' }}>
                        <span style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>Description</span>
                        <input type="text" value={newSrpDesc} onChange={(e) => setNewSrpDesc(e.target.value)} placeholder="Block executions" style={{ padding: '6px' }} />
                      </div>
                      <button onClick={addSrpRule} className="btn btn-secondary" style={{ padding: '8px 14px' }}>
                        <Plus size={14} /> Add
                      </button>
                    </div>
                  </div>
                )}
              </div>

              {/* Feature: Firewall controls */}
              <div className="glass-panel">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                  <h3 style={{ fontSize: '15px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <ShieldCheck size={16} style={{ color: 'var(--status-online)' }} /> Firewall Rules Manager
                  </h3>
                  <label className="toggle-switch">
                    <input type="checkbox" checked={fwEnabled} onChange={(e) => setFwEnabled(e.target.checked)} />
                    <span className="toggle-slider"></span>
                  </label>
                </div>

                {fwEnabled && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                    <label style={{ display: 'flex', gap: '10px', alignItems: 'center', cursor: 'pointer' }}>
                      <input type="checkbox" checked={fwGlobalState} onChange={(e) => setFwGlobalState(e.target.checked)} style={{ width: 'auto' }} />
                      <span style={{ fontSize: '13px' }}>Enforce Global firewall State (State = ON)</span>
                    </label>

                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Rule Name</th>
                          <th>Direction</th>
                          <th>Action</th>
                          <th>Port</th>
                          <th style={{ textAlign: 'right' }}>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {fwRules.map(rule => (
                          <tr key={rule.name}>
                            <td style={{ fontWeight: 600 }}>WWPO_{rule.name}</td>
                            <td style={{ textTransform: 'uppercase' }}>{rule.direction}</td>
                            <td>
                              <span style={{ 
                                padding: '2px 6px', 
                                borderRadius: '4px', 
                                fontSize: '10px', 
                                fontWeight: 700, 
                                background: rule.action === 'allow' ? 'rgba(16,185,129,0.1)' : 'rgba(239,68,68,0.1)',
                                color: rule.action === 'allow' ? 'var(--status-online)' : 'var(--status-offline)'
                              }}>
                                {rule.action}
                              </span>
                            </td>
                            <td style={{ fontFamily: 'var(--font-mono)' }}>{rule.local_port}</td>
                            <td style={{ textAlign: 'right' }}>
                              <button onClick={() => setFwRules(fwRules.filter(r => r.name !== rule.name))} style={{ background: 'transparent', color: 'var(--status-offline)' }}>
                                <Trash2 size={13} />
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

            </div>
          </div>
        )}

        {/* TAB 3: Enrolled Agents */}
        {activeTab === 'agents' && (
          <div className="glass-panel">
            <div className="panel-header">
              <div className="panel-title">
                <Laptop style={{ color: 'var(--color-primary)' }} size={16} /> Enrolled Active Hosts
              </div>
            </div>

            <table className="data-table">
              <thead>
                <tr>
                  <th>Hostname</th>
                  <th>IP Address</th>
                  <th>Logical Workgroup</th>
                  <th>Operating System</th>
                  <th>Connection Status</th>
                  <th>Last Seen</th>
                  <th style={{ fontFamily: 'var(--font-mono)' }}>Agent ID</th>
                </tr>
              </thead>
              <tbody>
                {agents.length === 0 ? (
                  <tr>
                    <td colSpan="7" style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                      No active security agents are currently registered with this master node.
                    </td>
                  </tr>
                ) : (
                  agents.map(agent => (
                    <tr key={agent.agent_id} style={{ cursor: 'pointer' }} onClick={() => setSelectedAgentForModal(agent)} title="Click to view client applications and firewall rules telemetry">
                      <td style={{ fontWeight: 600 }}>{agent.hostname}</td>
                      <td style={{ fontFamily: 'var(--font-mono)' }}>{agent.ip_address}</td>
                      <td>
                        <span style={{ 
                          fontFamily: 'var(--font-mono)', 
                          fontSize: '11px', 
                          background: 'rgba(99, 102, 241, 0.1)', 
                          color: 'var(--color-primary)', 
                          padding: '2px 6px', 
                          borderRadius: '4px',
                          border: '1px solid rgba(99, 102, 241, 0.2)' 
                        }}>
                          {agent.workgroup}
                        </span>
                      </td>
                      <td>{agent.os_version}</td>
                      <td>
                        <span className={`badge ${agent.status === 'online' ? 'badge-online' : 'badge-offline'}`}>
                          <span className={`status-indicator ${agent.status === 'online' ? 'status-indicator-online' : 'status-indicator-offline'}`} style={{ width: '5px', height: '5px', marginRight: '0' }}></span>
                          {agent.status}
                        </span>
                      </td>
                      <td>{agent.last_seen && agent.last_seen !== '0001-01-01T00:00:00Z' ? new Date(agent.last_seen).toLocaleString() : 'Never'}</td>
                      <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', fontSize: '11px' }}>{agent.agent_id.substring(0, 10)}...</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}

        {/* TAB 4: Setup Tokens */}
        {activeTab === 'tokens' && (
          <div className="dashboard-grid" style={{ gridTemplateColumns: '1.2fr 1.8fr' }}>
            {/* Generate Token card */}
            <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div className="panel-header" style={{ marginBottom: '0' }}>
                <div className="panel-title">
                  <Key style={{ color: 'var(--color-primary)' }} size={16} /> Token parameters
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <span className="stat-label">Assign Workgroup identity</span>
                <input 
                  type="text" 
                  value={tokenWorkgroup} 
                  onChange={(e) => setTokenWorkgroup(e.target.value.toUpperCase())}
                  placeholder="e.g. FINANCE_DEPT"
                  style={{ textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}
                />
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>Expiration lifetime:</span>
                  <span style={{ fontWeight: 700, color: 'var(--color-primary)' }}>{tokenDuration} Minutes</span>
                </div>
                <input 
                  type="range" 
                  min="10" 
                  max="1440" 
                  value={tokenDuration} 
                  onChange={(e) => setTokenDuration(e.target.value)} 
                />
              </div>

              <button onClick={generateToken} className="btn btn-primary" style={{ width: '100%', marginTop: '10px' }}>
                <Plus size={16} /> Create Setup Token
              </button>
            </div>

            {/* Token details and PowerShell instructions */}
            <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              {generatedToken ? (
                <>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--status-online)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <ShieldCheck size={16} /> Enrollment Token generated
                    </div>
                    <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Expires: {new Date(generatedToken.expires_at).toLocaleTimeString()}</span>
                  </div>

                  <div style={{ 
                    display: 'flex', 
                    alignItems: 'center', 
                    justifyContent: 'space-between', 
                    background: 'rgba(0,0,0,0.3)', 
                    border: '1px solid var(--border-color)', 
                    padding: '12px 16px', 
                    borderRadius: '8px', 
                    fontFamily: 'var(--font-mono)', 
                    fontSize: '13px' 
                  }}>
                    <span style={{ color: 'var(--color-cyan)' }}>{generatedToken.token_value}</span>
                    <button onClick={() => copyToClipboard(generatedToken.token_value)} className="btn btn-secondary" style={{ padding: '6px 10px', fontSize: '11px' }}>
                      {copiedToken ? <Check size={12} style={{ color: 'var(--status-online)' }} /> : <Copy size={12} />}
                      {copiedToken ? ' Copied' : ' Copy'}
                    </button>
                  </div>

                  <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '16px' }}>
                    <span style={{ fontSize: '11px', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-secondary)', display: 'block', marginBottom: '8px' }}>
                      Agent config setup template:
                    </span>
                    <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '8px' }}>
                      Create a file on the target computer at <code>C:\ProgramData\WWPO\config.json</code> (or <code>./WWPO_Data/config.json</code> for testing) with this content:
                    </p>
                    <pre style={{ 
                      background: 'rgba(0,0,0,0.4)', 
                      border: '1px solid var(--border-color)', 
                      padding: '12px', 
                      borderRadius: '6px', 
                      fontFamily: 'var(--font-mono)', 
                      fontSize: '11px', 
                      color: 'var(--color-primary)',
                      overflowX: 'auto'
                    }}>
{`{
  "master_ip": "127.0.0.1",
  "setup_token": "${generatedToken.token_value}",
  "workgroup": "${generatedToken.workgroup}"
}`}
                    </pre>
                  </div>
                </>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: '12px', color: 'var(--text-muted)' }}>
                  <Key style={{ opacity: 0.15 }} size={48} />
                  <p style={{ fontSize: '13px' }}>Configure token parameters and submit to generate credentials.</p>
                </div>
              )}
            </div>
          </div>
        )}

      </main>

      {/* Agent details Modal */}
      {selectedAgentForModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.75)',
          backdropFilter: 'blur(8px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 9999,
          padding: '24px'
        }}>
          <div className="glass-panel" style={{
            width: '100%',
            maxWidth: '1000px',
            maxHeight: '90vh',
            overflowY: 'auto',
            display: 'flex',
            flexDirection: 'column',
            gap: '24px',
            border: '1px solid rgba(255, 255, 255, 0.15)',
            boxShadow: '0 20px 50px rgba(0,0,0,0.6)'
          }}>
            {/* Modal Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-color)', paddingBottom: '16px' }}>
              <div>
                <h2 style={{ fontSize: '20px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <Laptop style={{ color: 'var(--color-primary)' }} size={20} /> Endpoint: {selectedAgentForModal.hostname}
                </h2>
                <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                  Logical Domain: <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-cyan)' }}>{selectedAgentForModal.workgroup}</span> | IP: {selectedAgentForModal.ip_address} | OS: {selectedAgentForModal.os_version}
                </p>
              </div>
              <button 
                onClick={() => { setSelectedAgentForModal(null); setAppSearchQuery(''); }} 
                className="btn btn-secondary" 
                style={{ padding: '6px 12px' }}
              >
                Close
              </button>
            </div>

            {/* Modal Content Columns */}
            <div className="dashboard-grid" style={{ gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
              {/* Left Column: Installed Apps */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <h3 style={{ fontSize: '14px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Activity size={14} style={{ color: 'var(--color-cyan)' }} /> Installed Applications ({(() => {
                    try {
                      return JSON.parse(selectedAgentForModal.installed_apps || '[]').length;
                    } catch(e) { return 0; }
                  })()})
                </h3>

                <input 
                  type="text" 
                  placeholder="Filter installed apps..." 
                  value={appSearchQuery} 
                  onChange={(e) => setAppSearchQuery(e.target.value)}
                  style={{ padding: '8px 12px', background: 'rgba(0,0,0,0.2)' }}
                />

                <div style={{ 
                  maxHeight: '320px', 
                  overflowY: 'auto', 
                  background: 'rgba(0,0,0,0.2)', 
                  border: '1px solid var(--border-color)',
                  borderRadius: '8px',
                  padding: '12px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '6px'
                }}>
                  {(() => {
                    try {
                      const apps = JSON.parse(selectedAgentForModal.installed_apps || '[]');
                      const filtered = apps.filter(app => app.toLowerCase().includes(appSearchQuery.toLowerCase()));
                      if (filtered.length === 0) {
                        return <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>No applications found.</span>;
                      }
                      return filtered.map((app, idx) => (
                        <div key={idx} style={{ 
                          fontSize: '12px', 
                          padding: '6px 10px', 
                          background: 'rgba(255,255,255,0.03)', 
                          borderRadius: '4px',
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center'
                        }}>
                          <span>{app}</span>
                          <button 
                            onClick={() => {
                              setSelectedWorkgroup(selectedAgentForModal.workgroup);
                              // Auto add SRP path restriction rule for this app
                              const cleanName = app.replace(/[^a-zA-Z0-9]/g, '');
                              const targetValue = `*%${cleanName}%*.exe`;

                              const exists = srpRules.some(r => r.value.toLowerCase() === targetValue.toLowerCase());
                              if (exists) {
                                setSelectedAgentForModal(null);
                                setActiveTab('policies');
                                showNotice('info', `Software restriction rule for "${app}" already exists.`);
                                return;
                              }

                              const rule = {
                                id: `rule-${Math.random().toString(36).substr(2, 5)}`,
                                type: 'path',
                                value: targetValue,
                                action: 'disallow',
                                hash_alg: 'sha256',
                                file_size_bytes: 0,
                                description: `Restrict execution of ${app}`
                              };
                              setSrpRules(prev => [...prev, rule]);
                              setSelectedAgentForModal(null);
                              setActiveTab('policies');
                              showNotice('success', `Added software restriction rule for ${app}. Click Deploy to push.`);
                            }}
                            className="btn btn-secondary" 
                            style={{ padding: '2px 6px', fontSize: '10px' }}
                          >
                            Restrict Execution
                          </button>
                        </div>
                      ));
                    } catch(e) {
                      return <span style={{ fontSize: '12px', color: 'red' }}>Corrupted telemetry data.</span>;
                    }
                  })()}
                </div>
              </div>

              {/* Right Column: Firewall Rules */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <h3 style={{ fontSize: '14px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <ShieldCheck size={14} style={{ color: 'var(--status-online)' }} /> Detected Firewall Rules ({(() => {
                    try {
                      return JSON.parse(selectedAgentForModal.firewall_rules || '[]').length;
                    } catch(e) { return 0; }
                  })()})
                </h3>

                <div style={{ 
                  maxHeight: '380px', 
                  overflowY: 'auto', 
                  background: 'rgba(0,0,0,0.2)', 
                  border: '1px solid var(--border-color)',
                  borderRadius: '8px',
                  padding: '12px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '10px'
                }}>
                  {(() => {
                    try {
                      const rules = JSON.parse(selectedAgentForModal.firewall_rules || '[]');
                      if (rules.length === 0) {
                        return <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>No firewall rules reported.</span>;
                      }
                      return rules.map((rule, idx) => (
                        <div key={idx} style={{ 
                          background: 'rgba(255,255,255,0.02)', 
                          padding: '10px', 
                          borderRadius: '6px', 
                          border: '1px solid rgba(255,255,255,0.03)',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '6px'
                        }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ fontWeight: 600, fontSize: '12px', color: 'var(--text-primary)' }}>{rule.name}</span>
                            <span style={{ 
                              fontSize: '9px', 
                              padding: '2px 6px', 
                              borderRadius: '4px',
                              background: rule.action === 'allow' ? 'rgba(16,185,129,0.1)' : 'rgba(239,68,68,0.1)',
                              color: rule.action === 'allow' ? 'var(--status-online)' : 'var(--status-offline)',
                              fontWeight: 700,
                              textTransform: 'uppercase'
                            }}>
                              {rule.action}
                            </span>
                          </div>
                          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--text-secondary)' }}>
                            <span>Dir: <strong style={{ textTransform: 'uppercase' }}>{rule.direction}</strong> | Proto: {rule.protocol || 'any'} | Port: {rule.local_port || 'any'}</span>
                            <button 
                              onClick={() => {
                                setSelectedWorkgroup(selectedAgentForModal.workgroup);
                                // Check if rule name already exists in state
                                const exists = fwRules.some(r => r.name.toLowerCase() === rule.name.toLowerCase());
                                if (exists) {
                                  setSelectedAgentForModal(null);
                                  setActiveTab('policies');
                                  showNotice('info', `Firewall rule "${rule.name}" already exists.`);
                                  return;
                                }
                                setFwRules(prev => [...prev, {
                                  name: rule.name,
                                  direction: rule.direction,
                                  action: rule.action,
                                  protocol: rule.protocol || 'TCP',
                                  local_port: rule.local_port || 'any',
                                  remote_port: 'any',
                                  remote_ip: rule.remote_ip || 'any'
                                }]);
                                setSelectedAgentForModal(null);
                                setActiveTab('policies');
                                showNotice('success', `Promoted rule "${rule.name}" to workgroup policy! Click Deploy to push.`);
                              }}
                              className="btn btn-secondary" 
                              style={{ padding: '3px 8px', fontSize: '10px', color: 'var(--color-primary)', borderColor: 'rgba(99, 102, 241, 0.3)' }}
                            >
                              Promote to Policy
                            </button>
                          </div>
                        </div>
                      ));
                    } catch(e) {
                      return <span style={{ fontSize: '12px', color: 'red' }}>Corrupted telemetry data.</span>;
                    }
                  })()}
                </div>
              </div>
            </div>

          </div>
        </div>
      )}
    </div>
  );
}
