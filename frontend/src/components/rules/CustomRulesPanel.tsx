import { useState } from 'react';
import {
  useRules,
  useCreateRule,
  useValidateRule,
  useDryRunRule,
  useForkRule,
  type CustomRule,
} from '@/api/hooks/useCustomRules';
import { useToast } from '@/lib/use-toast';

// ---------------------------------------------------------------------------
// Exported constants (tested)
// ---------------------------------------------------------------------------

export const LANGUAGE_OPTIONS = [
  { value: '', label: 'All Languages' },
  { value: 'python', label: 'Python' },
  { value: 'java', label: 'Java' },
  { value: 'go', label: 'Go' },
  { value: 'javascript', label: 'JavaScript' },
  { value: 'typescript', label: 'TypeScript' },
  { value: 'csharp', label: 'C#' },
  { value: 'ruby', label: 'Ruby' },
  { value: 'rust', label: 'Rust' },
  { value: 'php', label: 'PHP' },
  { value: 'kotlin', label: 'Kotlin' },
  { value: 'swift', label: 'Swift' },
  { value: 'cpp', label: 'C/C++' },
];

export const SOURCE_OPTIONS = [
  { value: '', label: 'All Sources' },
  { value: 'built-in', label: 'Built-in' },
  { value: 'custom', label: 'Custom' },
];

const SEVERITY_OPTIONS = [
  { value: '', label: 'All Severities' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
];

// ---------------------------------------------------------------------------
// Rule Upload Modal
// ---------------------------------------------------------------------------

interface UploadModalProps {
  onClose: () => void;
}

function RuleUploadModal({ onClose }: UploadModalProps): React.ReactElement {
  const [yaml, setYaml] = useState('');
  const [name, setName] = useState('');
  const [language, setLanguage] = useState('python');
  const [severity, setSeverity] = useState('high');
  const { toast } = useToast();

  const validateRule = useValidateRule();
  const dryRunRule = useDryRunRule();
  const createRule = useCreateRule();

  const [validationResult, setValidationResult] = useState<{
    valid: boolean;
    errors: string[];
  } | null>(null);
  const [dryRunResult, setDryRunResult] = useState<{
    matchCount: number;
    sampleMatches: { file: string; line: number; snippet: string }[];
  } | null>(null);

  const handleValidate = () => {
    validateRule.mutate(
      { yaml },
      {
        onSuccess: (result) => setValidationResult(result),
        onError: () =>
          setValidationResult({ valid: false, errors: ['Validation request failed'] }),
      },
    );
  };

  const handleDryRun = () => {
    dryRunRule.mutate(
      { yaml },
      {
        onSuccess: (result) => setDryRunResult(result),
        onError: () => toast({ title: 'Dry run failed', variant: 'error' }),
      },
    );
  };

  const handleActivate = () => {
    createRule.mutate(
      { yaml, name, language, severity },
      {
        onSuccess: () => {
          toast({ title: 'Rule created successfully', variant: 'success' });
          onClose();
        },
        onError: () => toast({ title: 'Failed to create rule', variant: 'error' }),
      },
    );
  };

  return (
    <div
      data-testid="rule-upload-modal"
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.5)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className="card"
        style={{ width: '600px', maxHeight: '85vh', overflow: 'auto' }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="card-title">Upload Custom Rule</div>

        {/* Name */}
        <div style={{ marginBottom: '8px' }}>
          <label className="field-label" htmlFor="rule-name">
            Rule Name
          </label>
          <input
            id="rule-name"
            className="input"
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Custom SHA-1 Detection"
          />
        </div>

        {/* Language + Severity row */}
        <div style={{ display: 'flex', gap: '8px', marginBottom: '8px' }}>
          <div style={{ flex: 1 }}>
            <label className="field-label" htmlFor="rule-language">
              Language
            </label>
            <select
              id="rule-language"
              className="input"
              value={language}
              onChange={(e) => setLanguage(e.target.value)}
            >
              {LANGUAGE_OPTIONS.filter((l) => l.value !== '').map((l) => (
                <option key={l.value} value={l.value}>
                  {l.label}
                </option>
              ))}
            </select>
          </div>
          <div style={{ flex: 1 }}>
            <label className="field-label" htmlFor="rule-severity">
              Severity
            </label>
            <select
              id="rule-severity"
              className="input"
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            >
              {SEVERITY_OPTIONS.filter((s) => s.value !== '').map((s) => (
                <option key={s.value} value={s.value}>
                  {s.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* YAML textarea */}
        <div style={{ marginBottom: '12px' }}>
          <label className="field-label" htmlFor="rule-yaml">
            Rule YAML
          </label>
          <textarea
            id="rule-yaml"
            className="input"
            rows={10}
            value={yaml}
            onChange={(e) => {
              setYaml(e.target.value);
              setValidationResult(null);
              setDryRunResult(null);
            }}
            placeholder={`rules:\n  - id: custom-my-rule\n    patterns:\n      - pattern: hashlib.md5(...)`}
            style={{ fontFamily: 'var(--font-mono, monospace)', fontSize: '12px', resize: 'vertical' }}
          />
        </div>

        {/* Validation result */}
        {validationResult && (
          <div
            data-testid="validation-result"
            className={`alert ${validationResult.valid ? 'alert-success' : 'alert-error'}`}
            style={{ marginBottom: '8px', fontSize: '12px' }}
          >
            {validationResult.valid
              ? 'YAML is valid'
              : validationResult.errors.join(', ')}
          </div>
        )}

        {/* Dry run result */}
        {dryRunResult && (
          <div
            data-testid="dry-run-result"
            className="alert alert-warn"
            style={{ marginBottom: '8px', fontSize: '12px' }}
          >
            <strong>{dryRunResult.matchCount} matches</strong> found.
            {dryRunResult.sampleMatches.length > 0 && (
              <div style={{ marginTop: '4px' }}>
                {dryRunResult.sampleMatches.map((m, idx) => (
                  <div key={idx} style={{ fontSize: '11px', color: 'var(--text-3)' }}>
                    {m.file}:{m.line} — <code>{m.snippet}</code>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Actions */}
        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
          <button className="btn btn-outline" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn btn-outline"
            disabled={!yaml || validateRule.isPending}
            onClick={handleValidate}
          >
            {validateRule.isPending ? 'Validating...' : 'Validate'}
          </button>
          <button
            className="btn btn-outline"
            disabled={!yaml || dryRunRule.isPending}
            onClick={handleDryRun}
          >
            {dryRunRule.isPending ? 'Running...' : 'Dry Run'}
          </button>
          <button
            className="btn btn-accent"
            disabled={!yaml || !name || createRule.isPending}
            onClick={handleActivate}
          >
            {createRule.isPending ? 'Creating...' : 'Activate'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Fork Modal
// ---------------------------------------------------------------------------

interface ForkModalProps {
  rule: CustomRule;
  onClose: () => void;
}

function ForkModal({ rule, onClose }: ForkModalProps): React.ReactElement {
  const forkRule = useForkRule();
  const { toast } = useToast();
  const [forkedYaml, setForkedYaml] = useState<string | null>(null);

  const handleFork = () => {
    forkRule.mutate(
      { ruleId: rule.id },
      {
        onSuccess: (result) => {
          setForkedYaml(result.yaml);
          toast({ title: `Forked as ${result.id}`, variant: 'success' });
        },
        onError: () => toast({ title: 'Failed to fork rule', variant: 'error' }),
      },
    );
  };

  return (
    <div
      data-testid="fork-modal"
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.5)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className="card"
        style={{ width: '500px', maxHeight: '70vh', overflow: 'auto' }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="card-title">Fork Rule: {rule.name}</div>

        <p style={{ fontSize: '12px', color: 'var(--text-2)', marginBottom: '12px' }}>
          Creates a custom copy of this built-in rule that you can edit independently.
          The original rule remains unchanged.
        </p>

        {forkedYaml && (
          <div style={{ marginBottom: '12px' }}>
            <div className="field-label">Forked Rule YAML</div>
            <textarea
              className="input"
              rows={8}
              value={forkedYaml}
              readOnly
              style={{ fontFamily: 'var(--font-mono, monospace)', fontSize: '12px' }}
            />
          </div>
        )}

        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
          <button className="btn btn-outline" onClick={onClose}>
            {forkedYaml ? 'Close' : 'Cancel'}
          </button>
          {!forkedYaml && (
            <button
              className="btn btn-accent"
              disabled={forkRule.isPending}
              onClick={handleFork}
            >
              {forkRule.isPending ? 'Forking...' : 'Fork Rule'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Panel
// ---------------------------------------------------------------------------

export function CustomRulesPanel(): React.ReactElement {
  const [search, setSearch] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');
  const [languageFilter, setLanguageFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [showUpload, setShowUpload] = useState(false);
  const [forkTarget, setForkTarget] = useState<CustomRule | null>(null);

  const { data: rules, isLoading } = useRules({
    source: sourceFilter || undefined,
    language: languageFilter || undefined,
    severity: severityFilter || undefined,
    search: search || undefined,
  });

  return (
    <div>
      {/* Header */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '12px',
        }}
      >
        <div className="card-title" style={{ margin: 0 }}>
          Detection Rules
        </div>
        <button
          className="btn btn-accent"
          style={{ fontSize: '11px', padding: '4px 12px' }}
          onClick={() => setShowUpload(true)}
          data-testid="upload-rule-btn"
        >
          + Upload Rule
        </button>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: '8px', marginBottom: '12px', flexWrap: 'wrap' }}>
        <input
          className="input"
          type="text"
          placeholder="Search rules..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ flex: '1 1 200px', fontSize: '12px' }}
          aria-label="Search rules"
          data-testid="rule-search"
        />
        <select
          className="filter"
          value={sourceFilter}
          onChange={(e) => setSourceFilter(e.target.value)}
          aria-label="Filter by source"
          data-testid="source-filter"
        >
          {SOURCE_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
        <select
          className="filter"
          value={languageFilter}
          onChange={(e) => setLanguageFilter(e.target.value)}
          aria-label="Filter by language"
          data-testid="language-filter"
        >
          {LANGUAGE_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
        <select
          className="filter"
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          aria-label="Filter by severity"
          data-testid="severity-filter"
        >
          {SEVERITY_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      </div>

      {/* Rules table */}
      {isLoading ? (
        <div style={{ color: 'var(--text-3)', fontSize: '12px', padding: '12px' }}>
          Loading rules...
        </div>
      ) : (
        <table>
          <thead>
            <tr>
              <th scope="col">Rule</th>
              <th scope="col">Language</th>
              <th scope="col">Severity</th>
              <th scope="col">Source</th>
              <th scope="col">Status</th>
              <th scope="col">Actions</th>
            </tr>
          </thead>
          <tbody>
            {rules?.map((rule) => (
              <tr key={rule.id} data-testid={`custom-rule-${rule.id}`}>
                <td>
                  <div style={{ fontWeight: 600, fontSize: '12px' }}>{rule.name}</div>
                  <div style={{ fontSize: '10px', color: 'var(--text-3)', marginTop: '2px' }}>
                    {rule.description}
                  </div>
                </td>
                <td>
                  <span
                    style={{
                      fontSize: '10px',
                      padding: '2px 6px',
                      borderRadius: 'var(--radius)',
                      border: '1px solid var(--border)',
                      color: 'var(--text-3)',
                    }}
                  >
                    {rule.language}
                  </span>
                </td>
                <td>
                  <span
                    className={`badge ${
                      rule.severity === 'critical'
                        ? 'b-crit'
                        : rule.severity === 'high'
                          ? 'b-high'
                          : 'b-med'
                    }`}
                  >
                    {rule.severity}
                  </span>
                </td>
                <td>
                  <span
                    style={{
                      fontSize: '10px',
                      padding: '2px 6px',
                      borderRadius: 'var(--radius)',
                      background:
                        rule.source === 'custom'
                          ? 'var(--purple)'
                          : 'var(--bg-3)',
                      color: rule.source === 'custom' ? '#fff' : 'var(--text-2)',
                    }}
                  >
                    {rule.source}
                  </span>
                </td>
                <td>
                  <span
                    style={{
                      fontSize: '10px',
                      color: rule.enabled ? 'var(--green)' : 'var(--text-4)',
                    }}
                  >
                    {rule.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </td>
                <td>
                  {rule.source === 'built-in' && (
                    <button
                      className="btn btn-outline"
                      style={{ fontSize: '10px', padding: '2px 8px' }}
                      onClick={() => setForkTarget(rule)}
                      data-testid={`fork-btn-${rule.id}`}
                    >
                      Fork
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {rules && rules.length === 0 && (
              <tr>
                <td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-3)', fontSize: '12px', padding: '20px' }}>
                  No rules match the current filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      )}

      {/* Upload Modal */}
      {showUpload && <RuleUploadModal onClose={() => setShowUpload(false)} />}

      {/* Fork Modal */}
      {forkTarget && (
        <ForkModal rule={forkTarget} onClose={() => setForkTarget(null)} />
      )}
    </div>
  );
}
