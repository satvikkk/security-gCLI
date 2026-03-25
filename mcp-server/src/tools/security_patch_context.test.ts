/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { getSecurityPatchContextMessages, SecurityPatchContextArgs } from './security_patch_context.js';
import { VulnerabilityType } from '../knowledge.js';

// Mock knowledge loader
const knowledgeMocks = vi.hoisted(() => ({
  loadKnowledge: vi.fn(),
}));

vi.mock('../knowledge.js', async () => {
  const actual = await vi.importActual('../knowledge.js');
  return {
    ...actual,
    loadKnowledge: knowledgeMocks.loadKnowledge,
  };
});

// Mock fs
const fsMocks = vi.hoisted(() => ({
  readFile: vi.fn(),
}));

vi.mock('fs', async () => ({
  promises: {
    readFile: fsMocks.readFile,
  },
}));

describe('getSecurityPatchContextMessages', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should generate context with knowledge and file content', async () => {
    knowledgeMocks.loadKnowledge.mockResolvedValue('## Remediation Guide\nUse path.resolve');
    fsMocks.readFile.mockResolvedValue('const unsafe = req.query.path;');

    const args: SecurityPatchContextArgs = {
      vulnerability: VulnerabilityType.PathTraversal,
      filePath: '/app/server.ts',
      pocFilePath: '',
      vulnerabilityContext: 'Line 10: Unsafe input',
    };

    const result = await getSecurityPatchContextMessages(args);

    expect(result.content).toHaveLength(1);
    const content = result.content[0].text;

    expect(content).toContain('**Knowledge Base:**');
    expect(content).toContain('## Remediation Guide');
    expect(content).toContain('Use path.resolve');
    expect(content).toContain('const unsafe = req.query.path;');
    expect(content).toContain('Line 10: Unsafe input');
    expect(content).toContain('Invoke the security-patcher skill');
  });

  it('should handle file read error', async () => {
    knowledgeMocks.loadKnowledge.mockResolvedValue('## Remediation Guide');
    fsMocks.readFile.mockRejectedValue(new Error('Access denied'));

    const args: SecurityPatchContextArgs = {
      vulnerability: VulnerabilityType.PathTraversal,
      filePath: '/protected/file.ts',
      pocFilePath: '',
      vulnerabilityContext: 'Line 10: Unsafe input',
    };

    const result = await getSecurityPatchContextMessages(args);
    const content = result.content[0].text;

    expect(content).toContain('Error reading file: Access denied');
  });
});