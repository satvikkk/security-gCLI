/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, vi, expect } from 'vitest';
import { promises as fs, PathLike } from 'fs';
import { runPoc } from './poc.js';
import { POC_DIR, PATH_TRAVERSAL_TEMP_FILE } from './constants.js';

describe('runPoc', () => {
  const mockPath = {
    dirname: (p: string) => p.substring(0, p.lastIndexOf('/')),
    resolve: (p1: string, p2?: string) => {
      if (p2 && p2.startsWith('/')) return p2;
      if (p2) return p1 + '/' + p2;
      return p1;
    },
    join: (...paths: string[]) => paths.join('/'),
    extname: (p: string) => {
      const idx = p.lastIndexOf('.');
      return idx !== -1 ? p.substring(idx) : '';
    },
    basename: (p: string) => p.substring(p.lastIndexOf('/') + 1),
    sep: '/',
  };

  it('should execute a Node.js file', async () => {
    const mockExecAsync = vi.fn(async () => { return { stdout: '', stderr: '' }; });
    const mockExecFileAsync = vi.fn(async () => { return { stdout: 'output', stderr: '' }; });

    const result = await runPoc(
      { filePath: `${POC_DIR}/test.js` },
      { 
        fs: { 
          access: vi.fn().mockRejectedValue(new Error()),
          writeFile: vi.fn(),
        } as any, 
        path: mockPath as any, 
        execAsync: mockExecAsync as any, 
        execFileAsync: mockExecFileAsync as any 
      }
    );

    expect(mockExecAsync).toHaveBeenCalledTimes(0);
    expect(mockExecFileAsync).toHaveBeenCalledTimes(1);
    expect(mockExecFileAsync).toHaveBeenCalledWith('node', [`${POC_DIR}/test.js`], expect.any(Object));
    expect(result.stdout).toBe('output');
    expect(result.stderr).toBe('');
  });

  it('should execute a Python file', async () => {
    const mockExecAsync = vi.fn(async () => { return { stdout: '', stderr: '' }; });
    const mockExecFileAsync = vi.fn(async () => { return { stdout: 'output', stderr: '' }; });

    const result = await runPoc(
      { filePath: `${POC_DIR}/test.py` },
      { fs: { access: vi.fn().mockRejectedValue(new Error()), writeFile: vi.fn() } as any, path: mockPath as any, execAsync: mockExecAsync as any, execFileAsync: mockExecFileAsync as any }
    );

    expect(mockExecAsync).toHaveBeenCalledWith(expect.stringContaining('python3 -m venv'));
    expect(mockExecFileAsync).toHaveBeenCalledTimes(1);
    expect(mockExecFileAsync).toHaveBeenCalledWith(expect.stringContaining('python'), [`${POC_DIR}/test.py`], expect.any(Object));
    expect(result.stdout).toBe('output');
    expect(result.stderr).toBe('');
  });

  it('should execute a Go file', async () => {
    const mockExecAsync = vi.fn(async () => { return { stdout: '', stderr: '' }; });
    const mockExecFileAsync = vi.fn(async () => { return { stdout: 'output', stderr: '' }; });

    const result = await runPoc(
      { filePath: `${POC_DIR}/test.go` },
      { fs: { access: vi.fn().mockRejectedValue(new Error()), writeFile: vi.fn() } as any, path: mockPath as any, execAsync: mockExecAsync as any, execFileAsync: mockExecFileAsync as any }
    );

    expect(mockExecAsync).toHaveBeenCalledTimes(2);
    expect(mockExecAsync).toHaveBeenNthCalledWith(1, 'go mod init poc', { cwd: POC_DIR });
    expect(mockExecAsync).toHaveBeenNthCalledWith(2, 'go mod tidy', { cwd: POC_DIR });
    expect(mockExecFileAsync).toHaveBeenCalledTimes(1);
    expect(mockExecFileAsync).toHaveBeenCalledWith('go', ['run', `${POC_DIR}/test.go`], expect.any(Object));
    expect(result.stdout).toBe('output');
    expect(result.stderr).toBe('');
  });

  it('should handle execution errors', async () => {
    const mockExecAsync = vi.fn(async (cmd: string) => {
      return { stdout: '', stderr: '' };
    });
    const mockExecFileAsync = vi.fn(async (file: string, args?: string[]) => {
      throw new Error('Execution failed');
    });

    const result = await runPoc(
      { filePath: `${POC_DIR}/error.js` },
      { 
        fs: { readFile: vi.fn(async () => '') } as any, 
        path: mockPath as any, 
        execAsync: mockExecAsync as any, 
        execFileAsync: mockExecFileAsync as any 
      }
    );

    expect(result.error).toBe('Execution failed');
    expect(result.stdout).toBe('');
    expect(result.stderr).toBe('');
  });

  it('should fail when accessing file outside of allowed directory', async () => {
    const mockExecAsync = vi.fn();
    const mockExecFileAsync = vi.fn();

    const result = await runPoc(
      { filePath: '/tmp/malicious.js' },
      { fs: { writeFile: vi.fn() } as any, path: mockPath as any, execAsync: mockExecAsync as any, execFileAsync: mockExecFileAsync as any }
    );

    expect(result.isSecurityError).toBe(true);
    expect(result.error).toContain('Security Error: PoC execution is restricted');
    expect(mockExecAsync).not.toHaveBeenCalled();
    expect(mockExecFileAsync).not.toHaveBeenCalled();
  });

  it('should cleanup path traversal temp file if it exists', async () => {
    const mockExecAsync = vi.fn(async () => { return { stdout: '', stderr: '' }; });
    const mockExecFileAsync = vi.fn(async () => { return { stdout: 'output', stderr: '' }; });
    const mockAccess = vi.fn();
    const mockUnlink = vi.fn();

    mockAccess.mockImplementation(async (path: PathLike) => {
      if (typeof path === 'string' && path.includes(PATH_TRAVERSAL_TEMP_FILE)) {
        return undefined;
      }
      throw new Error('File not found');
    });

    await runPoc(
      { filePath: `${POC_DIR}/test.js` },
      {
        fs: {
          access: mockAccess,
          unlink: mockUnlink,
          readFile: vi.fn(async () => '')
        } as any,
        path: mockPath as any,
        execAsync: mockExecAsync as any,
        execFileAsync: mockExecFileAsync as any
      }
    );

    expect(mockUnlink).toHaveBeenCalledWith(expect.stringContaining(PATH_TRAVERSAL_TEMP_FILE));
  });
});

