/**
 * Mock data for the Migration Kanban board.
 * Cards represent quantum-vulnerable findings that need migration.
 */

export type KanbanColumnId = 'todo' | 'in-progress' | 'in-review' | 'done';
export type KanbanPriority = 'critical' | 'high' | 'medium' | 'low';

export interface KanbanCard {
  id: string;
  findingName: string;
  repo: string;
  repoId: string;
  language: string;
  framework: string;
  currentAlgorithm: string;
  recommendedReplacement: string;
  priority: KanbanPriority;
  assignee: string;
  deadline: string;
  cnsa20Deadline: string;
  findingLink: string;
  replacementGuidance: string;
  column: KanbanColumnId;
}

export interface KanbanColumn {
  id: KanbanColumnId;
  title: string;
  cards: KanbanCard[];
}

export const MOCK_KANBAN_CARDS: KanbanCard[] = [
  {
    id: 'k-001',
    findingName: 'RSA-2048 key generation',
    repo: 'payment-service',
    repoId: 'repo-1',
    language: 'Java',
    framework: 'JCA',
    currentAlgorithm: 'RSA-2048',
    recommendedReplacement: 'ML-KEM-768',
    priority: 'critical',
    assignee: 'Alice Chen',
    deadline: '2026-06-30',
    cnsa20Deadline: '2030-01-01',
    findingLink: '/repos/repo-1/findings',
    replacementGuidance:
      'Replace RSA key generation with ML-KEM-768 using the BouncyCastle PQC provider. Update KeyPairGenerator.getInstance() to use "ML-KEM" algorithm.',
    column: 'todo',
  },
  {
    id: 'k-002',
    findingName: 'ECDSA P-256 signatures',
    repo: 'auth-api',
    repoId: 'repo-2',
    language: 'Python',
    framework: 'cryptography',
    currentAlgorithm: 'ECDSA',
    recommendedReplacement: 'ML-DSA-65',
    priority: 'high',
    assignee: 'Bob Martinez',
    deadline: '2026-07-15',
    cnsa20Deadline: '2030-01-01',
    findingLink: '/repos/repo-2/findings',
    replacementGuidance:
      'Migrate from ECDSA to ML-DSA-65 (Dilithium) using the oqs-python library. Update signature generation and verification paths.',
    column: 'todo',
  },
  {
    id: 'k-003',
    findingName: 'ECDH key exchange',
    repo: 'payment-service',
    repoId: 'repo-1',
    language: 'Java',
    framework: 'JCA',
    currentAlgorithm: 'ECDH',
    recommendedReplacement: 'ML-KEM-768',
    priority: 'high',
    assignee: 'Alice Chen',
    deadline: '2026-08-01',
    cnsa20Deadline: '2030-01-01',
    findingLink: '/repos/repo-1/findings',
    replacementGuidance:
      'Replace ECDH key agreement with ML-KEM key encapsulation. Use hybrid mode (X25519 + ML-KEM) for backward compatibility during transition.',
    column: 'in-progress',
  },
  {
    id: 'k-004',
    findingName: 'RSA-4096 signing',
    repo: 'mobile-backend',
    repoId: 'repo-4',
    language: 'Kotlin',
    framework: 'BouncyCastle',
    currentAlgorithm: 'RSA-4096',
    recommendedReplacement: 'ML-DSA-87',
    priority: 'critical',
    assignee: 'Carol Singh',
    deadline: '2026-05-15',
    cnsa20Deadline: '2030-01-01',
    findingLink: '/repos/repo-4/findings',
    replacementGuidance:
      'Replace RSA-4096 signature operations with ML-DSA-87 (Dilithium5). Update all certificate chains that depend on this key.',
    column: 'in-progress',
  },
  {
    id: 'k-005',
    findingName: 'Ed25519 token signing',
    repo: 'auth-api',
    repoId: 'repo-2',
    language: 'Python',
    framework: 'PyNaCl',
    currentAlgorithm: 'Ed25519',
    recommendedReplacement: 'ML-DSA-44',
    priority: 'medium',
    assignee: 'Bob Martinez',
    deadline: '2026-09-30',
    cnsa20Deadline: '2033-01-01',
    findingLink: '/repos/repo-2/findings',
    replacementGuidance:
      'Migrate Ed25519 signing to ML-DSA-44 (Dilithium2). Consider hybrid signing (Ed25519 + ML-DSA) for phased rollout.',
    column: 'in-review',
  },
  {
    id: 'k-006',
    findingName: 'DH key exchange (legacy)',
    repo: 'data-pipeline',
    repoId: 'repo-3',
    language: 'Python',
    framework: 'cryptography',
    currentAlgorithm: 'DH-2048',
    recommendedReplacement: 'ML-KEM-512',
    priority: 'medium',
    assignee: 'David Lee',
    deadline: '2026-10-31',
    cnsa20Deadline: '2030-01-01',
    findingLink: '/repos/repo-3/findings',
    replacementGuidance:
      'Replace legacy DH key exchange with ML-KEM-512. The DH module in the data-pipeline is only used for internal service-to-service communication.',
    column: 'in-review',
  },
  {
    id: 'k-007',
    findingName: 'RSA-2048 TLS cert',
    repo: 'data-pipeline',
    repoId: 'repo-3',
    language: 'Python',
    framework: 'OpenSSL',
    currentAlgorithm: 'RSA-2048',
    recommendedReplacement: 'ML-DSA-65',
    priority: 'low',
    assignee: 'David Lee',
    deadline: '2026-12-31',
    cnsa20Deadline: '2030-01-01',
    findingLink: '/repos/repo-3/findings',
    replacementGuidance:
      'Update internal TLS certificates from RSA-2048 to ML-DSA-65. Coordinate with infrastructure team for CA update.',
    column: 'done',
  },
  {
    id: 'k-008',
    findingName: 'ECDSA P-384 API signing',
    repo: 'mobile-backend',
    repoId: 'repo-4',
    language: 'Java',
    framework: 'JCA',
    currentAlgorithm: 'ECDSA',
    recommendedReplacement: 'ML-DSA-65',
    priority: 'high',
    assignee: 'Carol Singh',
    deadline: '2026-07-31',
    cnsa20Deadline: '2030-01-01',
    findingLink: '/repos/repo-4/findings',
    replacementGuidance:
      'Replace ECDSA P-384 with ML-DSA-65 for API request signing. Update both client SDK and server verification logic.',
    column: 'done',
  },
];

export function getKanbanCards(): KanbanCard[] {
  return MOCK_KANBAN_CARDS;
}

export function getKanbanColumns(): KanbanColumn[] {
  const columnDefs: { id: KanbanColumnId; title: string }[] = [
    { id: 'todo', title: 'To Do' },
    { id: 'in-progress', title: 'In Progress' },
    { id: 'in-review', title: 'In Review' },
    { id: 'done', title: 'Done' },
  ];

  return columnDefs.map((col) => ({
    ...col,
    cards: MOCK_KANBAN_CARDS.filter((c) => c.column === col.id),
  }));
}
