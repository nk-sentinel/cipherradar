import { useState, useEffect } from 'react';
import { RequireRole } from '@/components/guards/RequireRole.tsx';
import {
  useLLMConfig,
  useSaveLLMConfig,
  useTestLLMConnection,
  LLM_PROVIDER_DEFAULTS,
  type LLMProviderType,
  type LLMConfig as LLMConfigType,
} from '@/api/hooks/useLLMConfig.ts';
import { useToast } from '@/lib/use-toast.ts';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PROVIDERS: { value: LLMProviderType; label: string; description: string }[] = [
  { value: 'anthropic', label: 'Anthropic', description: 'Claude models via Anthropic API' },
  { value: 'openai', label: 'OpenAI', description: 'GPT models via OpenAI API' },
  { value: 'ollama', label: 'Ollama', description: 'Self-hosted open-source models' },
  { value: 'custom', label: 'Custom', description: 'OpenAI-compatible endpoint' },
  { value: 'disabled', label: 'Disabled', description: 'AI features are turned off' },
];

const DEFAULT_CONFIG: LLMConfigType = {
  provider: 'disabled',
  apiUrl: '',
  apiKey: '',
  model: '',
  temperature: 0.2,
  maxTokens: 4096,
  privacy: {
    consentRequired: true,
    stripComments: false,
    anonymizeVariables: false,
  },
  customInstructions: '',
};

// ---------------------------------------------------------------------------
// Page export
// ---------------------------------------------------------------------------

export function LLMConfig(): React.ReactElement {
  return (
    <RequireRole roles={['org-admin']}>
      <LLMConfigContent />
    </RequireRole>
  );
}

// ---------------------------------------------------------------------------
// Content
// ---------------------------------------------------------------------------

function LLMConfigContent(): React.ReactElement {
  const { data: savedConfig, isLoading, error } = useLLMConfig();
  const saveConfig = useSaveLLMConfig();
  const testConnection = useTestLLMConnection();
  const { toast } = useToast();

  const [config, setConfig] = useState<LLMConfigType>(DEFAULT_CONFIG);
  const [testResult, setTestResult] = useState<{
    success: boolean;
    message: string;
    latencyMs?: number;
  } | null>(null);

  // Hydrate form when data loads
  useEffect(() => {
    if (savedConfig) {
      setConfig(savedConfig);
    }
  }, [savedConfig]);

  const updateField = <K extends keyof LLMConfigType>(key: K, value: LLMConfigType[K]) => {
    setConfig((prev) => ({ ...prev, [key]: value }));
  };

  const updatePrivacy = (key: keyof LLMConfigType['privacy'], value: boolean) => {
    setConfig((prev) => ({
      ...prev,
      privacy: { ...prev.privacy, [key]: value },
    }));
  };

  const handleProviderChange = (provider: LLMProviderType) => {
    const defaults = LLM_PROVIDER_DEFAULTS[provider];
    setConfig((prev) => ({
      ...prev,
      provider,
      apiUrl: defaults.url,
      model: defaults.model,
      apiKey: provider === prev.provider ? prev.apiKey : '',
    }));
    setTestResult(null);
  };

  const handleTestConnection = () => {
    testConnection.mutate(config, {
      onSuccess: (result) => {
        setTestResult(result);
      },
      onError: () => {
        setTestResult({ success: false, message: 'Connection test failed' });
      },
    });
  };

  const handleSave = () => {
    saveConfig.mutate(config, {
      onSuccess: () => {
        toast({ title: 'LLM configuration saved', variant: 'success' });
      },
      onError: () => {
        toast({ title: 'Failed to save configuration', variant: 'error' });
      },
    });
  };

  if (isLoading) {
    return (
      <div className="card">
        <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>Loading...</p>
      </div>
    );
  }

  if (error) {
    // Allow editing even if fetch fails (new installation)
  }

  const isDisabled = config.provider === 'disabled';

  return (
    <div>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '20px',
        }}
      >
        <h1
          style={{
            fontSize: '18px',
            fontWeight: 700,
            textTransform: 'var(--tt)' as React.CSSProperties['textTransform'],
            letterSpacing: '0.04em',
          }}
        >
          LLM Configuration
        </h1>
      </div>

      {/* Provider Selector */}
      <div className="card">
        <div className="card-title">Provider</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: '8px' }}>
          {PROVIDERS.map((p) => (
            <button
              key={p.value}
              data-testid={`provider-${p.value}`}
              className="btn"
              style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'flex-start',
                padding: '12px',
                border: `2px solid ${config.provider === p.value ? 'var(--accent)' : 'var(--border)'}`,
                background: config.provider === p.value ? 'var(--bg-2)' : 'var(--bg-0)',
                borderRadius: 'var(--radius)',
                cursor: 'pointer',
                textAlign: 'left',
              }}
              onClick={() => handleProviderChange(p.value)}
            >
              <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-1)' }}>
                {p.label}
              </span>
              <span style={{ fontSize: '10px', color: 'var(--text-3)', marginTop: '4px' }}>
                {p.description}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Connection Settings */}
      {!isDisabled && (
        <div className="card">
          <div className="card-title">Connection</div>

          {/* API URL */}
          <div style={{ marginBottom: '12px' }}>
            <label className="field-label" htmlFor="llm-api-url">
              API URL
            </label>
            <input
              id="llm-api-url"
              className="input"
              type="url"
              value={config.apiUrl}
              onChange={(e) => updateField('apiUrl', e.target.value)}
              placeholder="https://api.example.com"
            />
          </div>

          {/* API Key */}
          {config.provider !== 'ollama' && (
            <div style={{ marginBottom: '12px' }}>
              <label className="field-label" htmlFor="llm-api-key">
                API Key
              </label>
              <input
                id="llm-api-key"
                className="input"
                type="password"
                value={config.apiKey}
                onChange={(e) => updateField('apiKey', e.target.value)}
                placeholder="sk-..."
              />
            </div>
          )}

          {/* Model */}
          <div style={{ marginBottom: '12px' }}>
            <label className="field-label" htmlFor="llm-model">
              Model
            </label>
            <input
              id="llm-model"
              className="input"
              type="text"
              value={config.model}
              onChange={(e) => updateField('model', e.target.value)}
              placeholder="Model name"
            />
          </div>

          {/* Temperature */}
          <div style={{ marginBottom: '12px' }}>
            <label className="field-label" htmlFor="llm-temperature">
              Temperature: {config.temperature.toFixed(1)}
            </label>
            <input
              id="llm-temperature"
              type="range"
              min="0"
              max="1"
              step="0.1"
              value={config.temperature}
              onChange={(e) => updateField('temperature', parseFloat(e.target.value))}
              style={{ width: '100%' }}
            />
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-3)' }}>
              <span>Precise (0.0)</span>
              <span>Creative (1.0)</span>
            </div>
          </div>

          {/* Max Tokens */}
          <div style={{ marginBottom: '16px' }}>
            <label className="field-label" htmlFor="llm-max-tokens">
              Max Tokens
            </label>
            <input
              id="llm-max-tokens"
              className="input"
              type="number"
              min={256}
              max={128000}
              value={config.maxTokens}
              onChange={(e) => updateField('maxTokens', parseInt(e.target.value, 10) || 4096)}
            />
          </div>

          {/* Test Connection */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <button
              className="btn btn-outline"
              disabled={testConnection.isPending || !config.apiUrl}
              onClick={handleTestConnection}
            >
              {testConnection.isPending ? 'Testing...' : 'Test Connection'}
            </button>
            {testResult && (
              <span
                data-testid="llm-test-result"
                style={{
                  fontSize: '12px',
                  color: testResult.success ? 'var(--green)' : 'var(--red)',
                }}
              >
                {testResult.message}
                {testResult.latencyMs !== undefined && ` (${String(testResult.latencyMs)}ms)`}
              </span>
            )}
          </div>
        </div>
      )}

      {/* Privacy Settings */}
      {!isDisabled && (
        <div className="card">
          <div className="card-title">Privacy</div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', color: 'var(--text-1)' }}>
              <input
                type="checkbox"
                checked={config.privacy.consentRequired}
                onChange={(e) => updatePrivacy('consentRequired', e.target.checked)}
              />
              Require user consent before sending code to LLM
            </label>

            <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', color: 'var(--text-1)' }}>
              <input
                type="checkbox"
                checked={config.privacy.stripComments}
                onChange={(e) => updatePrivacy('stripComments', e.target.checked)}
              />
              Strip comments from code before sending
            </label>

            <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', color: 'var(--text-1)' }}>
              <input
                type="checkbox"
                checked={config.privacy.anonymizeVariables}
                onChange={(e) => updatePrivacy('anonymizeVariables', e.target.checked)}
              />
              Anonymize variable and function names
            </label>
          </div>
        </div>
      )}

      {/* Custom Instructions */}
      {!isDisabled && (
        <div className="card">
          <div className="card-title">Custom Instructions</div>
          <textarea
            className="input"
            rows={4}
            value={config.customInstructions}
            onChange={(e) => updateField('customInstructions', e.target.value)}
            placeholder="Optional: provide additional context or instructions for the LLM when generating remediations..."
            style={{ resize: 'vertical', fontFamily: 'inherit' }}
          />
        </div>
      )}

      {/* Save */}
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '16px' }}>
        <button
          className="btn btn-accent"
          disabled={saveConfig.isPending}
          onClick={handleSave}
        >
          {saveConfig.isPending ? 'Saving...' : 'Save Configuration'}
        </button>
      </div>
    </div>
  );
}
