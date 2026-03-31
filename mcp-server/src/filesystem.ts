/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { promises as fs } from 'fs';
import path from 'path';
import { IGNORED_EXTENSIONS, IGNORED_FILES, IGNORED_FOLDERS } from './constants.js';

/**
 * Checks if the current directory is a GitHub repository.
 * @returns True if the current directory is a GitHub repository, false otherwise.
 */
export const isGitHubRepository = (): boolean => {
  try {
    const remotes = (
      spawnSync('git', ['remote', '-v'], {
        encoding: 'utf-8',
      }).stdout || ''
    ).trim();

    const pattern = /github\.com/;

    return pattern.test(remotes);
  } catch (_error) {
    return false;
  }
};

/**
 * Gets a changelist of the repository between two commits.
 * Can compare between two commits, or get the diff of the working directory.
 * If no commits are provided, it gets the changelist of the working directory.
 * @param base The base commit branch or hash.
 * @param head The head commit branch or hash.
 * @returns The changelist as a string.
 */
export function getAuditScope(base?: string, head?: string): string {
    // Default to working directory diff if no commits are provided
    const args: string[] = ["diff"];

    // Add commit range if both base and head are provided
    if (base !== undefined && head !== undefined) {
        args.push(base, head);
    }
    // Otherwise, if this is a GitHub repository, use origin/HEAD as the base
    else if (isGitHubRepository()) {
        args.push('--merge-base', 'origin/HEAD');
    }
    try {
        const diff = (
        spawnSync('git', args, {
            encoding: 'utf-8',
        }).stdout || ''
        ).trim();

        return diff;
    } catch (_error) {
        return "";
    }
}

/**
 * Gets a list of relevant file paths for auditing, filtering out irrelevant files and folders.
 * Irrelevant files include documentation, tests, build artifacts, etc.
 * @returns A list of relevant file paths for auditing.
 */
export function getFilesToAudit(): string[] {
  try {
    const trackedFiles = (
      spawnSync('git', ['ls-files'], {
        encoding: 'utf-8',
      }).stdout || ''
    )
      .trim()
      .split('\n');

    const untrackedFiles = (
      spawnSync('git', ['ls-files', '--others', '--exclude-standard'], {
        encoding: 'utf-8',
      }).stdout || ''
    )
      .trim()
      .split('\n');

    const allFiles = [...trackedFiles, ...untrackedFiles].filter((f) => f !== '');

    return allFiles.filter((filePath) => {
      const parts = filePath.split('/');
      
      // Ignore if any part of the path is in IGNORED_FOLDERS
      if (parts.some(part => IGNORED_FOLDERS.includes(part))) {
        return false;
      }

      const fileName = parts.pop() || '';
      const fileNameLower = fileName.toLowerCase();

      // Ignore exact files
      if (IGNORED_FILES.some(file => fileNameLower === file.toLowerCase())) {
        return false;
      }

      // Ignore extensions
      if (IGNORED_EXTENSIONS.some(ext => fileNameLower.endsWith(ext.toLowerCase()))) {
        return false;
      }

      return true;
    });
  } catch (error) {
    console.error('Error reducing audit scope:', error);
    return [];
  }
}

/**
 * Gets the total line count of a list of files.
 * @param files A list of file paths.
 * @returns The total line count of all files.
 */
export const getLineCount = (files: string[]): number => {
  let totalLines = 0;
  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const lineCount = (content.match(/\n/g) || []).length;
      totalLines += lineCount;
    } catch (error) {
      console.error(`Error counting lines in file ${file}:`, error);
    }
  }
  return totalLines;
}

/**
 * Detects the primary programming language of the project in the current working directory.
 * @returns 'Node.js', 'Python', 'Go', or 'Unknown'.
 */
export async function detectProjectLanguage(): Promise<'Node.js' | 'Python' | 'Go' | 'Unknown'> {
  const cwd = process.cwd();
  try {
    const files = await fs.readdir(cwd);

    if (files.includes('package.json')) return 'Node.js';
    if (files.includes('go.mod')) return 'Go';
    if (files.includes('requirements.txt') || files.includes('pyproject.toml')) return 'Python';

    // Fallback: check extensions
    const extensions = new Set(files.map(f => path.extname(f).toLowerCase()));
    if (extensions.has('.js') || extensions.has('.ts')) return 'Node.js';
    if (extensions.has('.py')) return 'Python';
    if (extensions.has('.go')) return 'Go';

    return 'Unknown';
  } catch {
    return 'Unknown';
  }
}
