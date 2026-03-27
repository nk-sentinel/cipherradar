import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { ScheduleConfig } from '../../src/components/scan/ScheduleConfig';

const server = setupServer(
  http.get('/api/v1/projects/:projectId/schedule', () => {
    return HttpResponse.json({
      preset: 'daily',
      hour: 2,
      timezone: 'UTC',
      source: 'project',
      nextRun: '2026-03-28T02:00:00Z',
    });
  }),

  http.put('/api/v1/projects/:projectId/schedule', async ({ request }) => {
    const body = await request.json();
    return HttpResponse.json(body);
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: 'bypass' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function renderWithProviders(ui: React.ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });
  return render(
    <QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>,
  );
}

describe('ScheduleConfig', () => {
  it('renders preset buttons', async () => {
    renderWithProviders(<ScheduleConfig scopeType="projects" scopeId="proj-001" />);

    await waitFor(() => {
      expect(screen.getByTestId('schedule-presets')).toBeInTheDocument();
    });

    expect(screen.getByTestId('preset-off')).toBeInTheDocument();
    expect(screen.getByTestId('preset-daily')).toBeInTheDocument();
    expect(screen.getByTestId('preset-weekly')).toBeInTheDocument();
  });

  it('shows inherited source indicator', async () => {
    server.use(
      http.get('/api/v1/projects/:projectId/schedule', () => {
        return HttpResponse.json({
          preset: 'weekly',
          hour: 3,
          timezone: 'UTC',
          source: 'group',
          nextRun: '2026-03-30T03:00:00Z',
        });
      }),
    );

    renderWithProviders(<ScheduleConfig scopeType="projects" scopeId="proj-001" />);

    await waitFor(() => {
      expect(screen.getByTestId('schedule-source')).toHaveTextContent('Inherited from group');
    });
  });

  it('saves schedule configuration', async () => {
    renderWithProviders(<ScheduleConfig scopeType="projects" scopeId="proj-001" />);

    await waitFor(() => {
      expect(screen.getByTestId('schedule-save')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId('preset-weekly'));
    fireEvent.click(screen.getByTestId('schedule-save'));

    await waitFor(() => {
      expect(screen.getByTestId('schedule-save')).not.toBeDisabled();
    });
  });
});
