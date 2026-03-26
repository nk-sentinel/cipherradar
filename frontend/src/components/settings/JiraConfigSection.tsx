import { useState, useEffect } from 'react';
import {
  useJiraConfig,
  useSaveJiraConfig,
  type JiraScopeType,
  type JiraPriorityMapping,
} from '@/api/hooks/useJira';

interface JiraConfigSectionProps {
  scopeType: JiraScopeType;
  scopeId: string;
}

const DEFAULT_PRIORITY_MAPPING: JiraPriorityMapping = {
  critical: 'Highest',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

const JIRA_PRIORITIES = ['Highest', 'High', 'Medium', 'Low', 'Lowest'];
const ISSUE_TYPES = ['Bug', 'Task', 'Story'];
const SEVERITY_LEVELS: (keyof JiraPriorityMapping)[] = ['critical', 'high', 'medium', 'low'];

export function JiraConfigSection({
  scopeType,
  scopeId,
}: JiraConfigSectionProps): React.ReactElement {
  const { data: config, isLoading } = useJiraConfig(scopeType, scopeId);
  const saveConfig = useSaveJiraConfig(scopeType, scopeId);

  const [projectKey, setProjectKey] = useState('');
  const [issueType, setIssueType] = useState('Bug');
  const [priorityMapping, setPriorityMapping] = useState<JiraPriorityMapping>(DEFAULT_PRIORITY_MAPPING);
  const [assignee, setAssignee] = useState('');
  const [labels, setLabels] = useState('');
  const [initialized, setInitialized] = useState(false);

  // Populate form when config loads
  useEffect(() => {
    if (config && !initialized) {
      setProjectKey(config.jiraProjectKey);
      setIssueType(config.defaultIssueType);
      setPriorityMapping({
        critical: config.priorityMapping.critical ?? 'Highest',
        high: config.priorityMapping.high ?? 'High',
        medium: config.priorityMapping.medium ?? 'Medium',
        low: config.priorityMapping.low ?? 'Low',
      });
      setAssignee(config.defaultAssignee ?? '');
      setLabels(config.labels.join(', '));
      setInitialized(true);
    }
  }, [config, initialized]);

  const handlePriorityChange = (severity: keyof JiraPriorityMapping, value: string) => {
    setPriorityMapping((prev) => ({ ...prev, [severity]: value }));
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    saveConfig.mutate({
      jiraProjectKey: projectKey,
      defaultIssueType: issueType,
      priorityMapping,
      defaultAssignee: assignee,
      labels: labels
        .split(',')
        .map((l) => l.trim())
        .filter(Boolean),
    });
  };

  if (isLoading) {
    return (
      <div className="card" data-testid="jira-config-loading">
        <div style={{ fontSize: '12px', color: 'var(--text-3)' }}>Loading Jira configuration...</div>
      </div>
    );
  }

  // Show empty state if no config and we've finished loading
  if (!config && !isLoading) {
    return (
      <div className="card" data-testid="jira-config-empty">
        <div style={{ textAlign: 'center', padding: '24px' }}>
          <div style={{ fontSize: '14px', fontWeight: 600, marginBottom: '8px' }}>
            Jira Integration Not Configured
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text-3)', marginBottom: '16px' }}>
            Configure Jira integration to create issues directly from findings.
          </div>
          <button
            className="btn btn-accent"
            onClick={() => setInitialized(true)}
            data-testid="jira-config-setup"
          >
            Set Up Jira
          </button>
        </div>
        {initialized && (
          <JiraConfigForm
            projectKey={projectKey}
            issueType={issueType}
            priorityMapping={priorityMapping}
            assignee={assignee}
            labels={labels}
            isPending={saveConfig.isPending}
            onProjectKeyChange={setProjectKey}
            onIssueTypeChange={setIssueType}
            onPriorityChange={handlePriorityChange}
            onAssigneeChange={setAssignee}
            onLabelsChange={setLabels}
            onSubmit={handleSubmit}
          />
        )}
      </div>
    );
  }

  return (
    <div className="card">
      <div style={{ fontSize: '14px', fontWeight: 700, marginBottom: '16px' }}>
        Jira Configuration
      </div>
      <JiraConfigForm
        projectKey={projectKey}
        issueType={issueType}
        priorityMapping={priorityMapping}
        assignee={assignee}
        labels={labels}
        isPending={saveConfig.isPending}
        onProjectKeyChange={setProjectKey}
        onIssueTypeChange={setIssueType}
        onPriorityChange={handlePriorityChange}
        onAssigneeChange={setAssignee}
        onLabelsChange={setLabels}
        onSubmit={handleSubmit}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Internal form component
// ---------------------------------------------------------------------------

interface JiraConfigFormProps {
  projectKey: string;
  issueType: string;
  priorityMapping: JiraPriorityMapping;
  assignee: string;
  labels: string;
  isPending: boolean;
  onProjectKeyChange: (value: string) => void;
  onIssueTypeChange: (value: string) => void;
  onPriorityChange: (severity: keyof JiraPriorityMapping, value: string) => void;
  onAssigneeChange: (value: string) => void;
  onLabelsChange: (value: string) => void;
  onSubmit: (e: React.FormEvent) => void;
}

function JiraConfigForm({
  projectKey,
  issueType,
  priorityMapping,
  assignee,
  labels,
  isPending,
  onProjectKeyChange,
  onIssueTypeChange,
  onPriorityChange,
  onAssigneeChange,
  onLabelsChange,
  onSubmit,
}: JiraConfigFormProps): React.ReactElement {
  return (
    <form onSubmit={onSubmit}>
      {/* Project Key + Issue Type row */}
      <div style={{ display: 'flex', gap: '12px', marginBottom: '12px' }}>
        <div style={{ flex: 1 }}>
          <label className="field-label">Jira Project Key</label>
          <input
            type="text"
            className="input"
            style={{ width: '100%' }}
            value={projectKey}
            onChange={(e) => onProjectKeyChange(e.target.value)}
            placeholder="e.g. SEC"
            data-testid="jira-project-key"
          />
        </div>
        <div style={{ flex: 1 }}>
          <label className="field-label">Default Issue Type</label>
          <select
            className="input"
            style={{ width: '100%' }}
            value={issueType}
            onChange={(e) => onIssueTypeChange(e.target.value)}
            data-testid="jira-issue-type"
          >
            {ISSUE_TYPES.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Priority Mapping */}
      <div style={{ marginBottom: '12px' }}>
        <div className="field-label">Priority Mapping</div>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: '8px',
          }}
        >
          {SEVERITY_LEVELS.map((severity) => (
            <div
              key={severity}
              style={{ display: 'flex', alignItems: 'center', gap: '8px' }}
            >
              <span
                style={{
                  fontSize: '11px',
                  width: '60px',
                  textTransform: 'capitalize',
                  color: 'var(--text-2)',
                }}
              >
                {severity}
              </span>
              <select
                className="input"
                style={{ flex: 1 }}
                value={priorityMapping[severity]}
                onChange={(e) => onPriorityChange(severity, e.target.value)}
                data-testid={`priority-${severity}`}
              >
                {JIRA_PRIORITIES.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </select>
            </div>
          ))}
        </div>
      </div>

      {/* Default Assignee */}
      <div style={{ marginBottom: '12px' }}>
        <label className="field-label">Default Assignee</label>
        <input
          type="text"
          className="input"
          style={{ width: '100%' }}
          value={assignee}
          onChange={(e) => onAssigneeChange(e.target.value)}
          placeholder="e.g. security-lead@company.com"
          data-testid="jira-assignee"
        />
      </div>

      {/* Labels */}
      <div style={{ marginBottom: '16px' }}>
        <label className="field-label">Labels (comma-separated)</label>
        <input
          type="text"
          className="input"
          style={{ width: '100%' }}
          value={labels}
          onChange={(e) => onLabelsChange(e.target.value)}
          placeholder="e.g. crypto, cipherradar"
          data-testid="jira-labels"
        />
      </div>

      {/* Save */}
      <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
        <button
          className="btn btn-accent"
          type="submit"
          disabled={isPending || !projectKey.trim()}
          data-testid="jira-config-save"
        >
          {isPending ? 'Saving...' : 'Save Configuration'}
        </button>
      </div>
    </form>
  );
}
