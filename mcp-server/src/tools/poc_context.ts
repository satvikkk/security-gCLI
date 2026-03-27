/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { z } from 'zod';
import { promises as fs } from 'fs';
import path from 'path';
import { SECURITY_DIR_NAME, POC_DIR_NAME, PATH_TRAVERSAL_TEMP_FILE } from '../constants.js';
import { VulnerabilityType } from '../knowledge.js';
import { detectProjectLanguage } from '../filesystem.js';

export const POC_CONTEXT_TOOL_NAME = 'poc_context';
export const POC_CONTEXT_TOOL_DESCRIPTION = 'Sets up the necessary workspace and directories to test a vulnerability, returning the context variables needed to generate the PoC. Call this tool as part of the `poc` skill.';

export const PocContextArgsSchema = z.object({
  problemStatement: z.string().describe(
    'The raw description of the security problem or vulnerability provided by the user.'
  ),
  vulnerabilityType: z.enum([VulnerabilityType.PathTraversal, VulnerabilityType.Other]).describe(
    'You must infer this from the problemStatement if not provided. If the problem involves reading/writing files outside intended directories, select "path_traversal". Otherwise, select "other".'
  ),
  sourceCodeLocation: z.string().describe(
    'The exact file path and function/line number of the vulnerable code.'
  ),
});

export type PocContextArgs = z.infer<typeof PocContextArgsSchema>;

export async function getPocContext(args: PocContextArgs) {
  const { problemStatement, vulnerabilityType, sourceCodeLocation } = args;

  const language = await detectProjectLanguage();
  const pocDir = path.join(process.cwd(), SECURITY_DIR_NAME, POC_DIR_NAME);

  // Ensure PoC directory exists
  await fs.mkdir(pocDir, { recursive: true });

  let extraInstructions = '';
  const timestamp = Date.now();
  let ext = 'js'; // Default extension

  if (language === 'Node.js') {
    ext = 'ts';
  } else if (language === 'Python') {
    ext = 'py';
  } else if (language === 'Go') {
    ext = 'go';
  }

  const pocFileName = `poc_${vulnerabilityType}_${timestamp}.${ext}`;

  if (vulnerabilityType === 'path_traversal') {
    const tempFilePath = path.join(process.cwd(), PATH_TRAVERSAL_TEMP_FILE);
    extraInstructions = [
      '*   **Path Traversal Verification:**',
      `    *   A temporary file will automatically be created at '${tempFilePath}' whenever you execute the PoC.`,
      `    *   Your PoC script (running inside '${pocDir}') should attempt to read this file using the vulnerability.`,
      '    *   Construct the path to this file relative to the PoC directory (e.g., attempt to traverse up to the workspace root).',
      '    *   You DO NOT need to create or delete this file; I have handled that.',
    ].join('\n');
  }

  return {
    content: [
      {
        type: 'text' as const,
        text: JSON.stringify({
          context: {
            problemStatement,
            sourceCodeLocation,
            vulnerabilityType,
            language
          },
          pocDir,
          pocFileName,
          extraInstructions: extraInstructions
        }, null, 2),
      },
    ],
  };
}
