import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import './styles/globals.css';

async function enableMocking(): Promise<void> {
  if (!import.meta.env.DEV) {
    return;
  }

  const { worker } = await import('./mocks/browser');
  await worker.start({
    onUnhandledRequest: 'bypass',
  });
}

enableMocking().then(() => {
  const rootElement = document.getElementById('root');
  if (!rootElement) {
    throw new Error('Root element not found');
  }

  createRoot(rootElement).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
});
