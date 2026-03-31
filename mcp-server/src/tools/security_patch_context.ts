/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { z } from 'zod';
import { loadKnowledge, VulnerabilityType } from '../knowledge.js';
import { promises as fs } from 'fs';

export const SECURITY_PATCH_CONTEXT_TOOL_NAME = 'security_patch_context';
export const SECURITY_PATCH_CONTEXT_TOOL_DESCRIPTION = 'Fetches context about a security vulnerability in a given file. Do not call this tool directly from a user prompt; instead, you MUST invoke the `security-patcher` skill, which will orchestrate the use of this tool and the patching process.';

export const SecurityPatchContextArgsSchema = z.object({
  vulnerability: z.nativeEnum(VulnerabilityType).describe('The type of vulnerability to patch. You must infer this from the user\'s request or the problem context.'),
  filePath: z.string().describe('The absolute path to the file that needs patching. You must provide the exact path.'),
  pocFilePath: z.string().describe('The absolute path to the PoC file that demonstrates the vulnerability. You must provide the exact path, or an empty string if the PoC does not exist.'),
  vulnerabilityContext: z.string().describe('A description of the vulnerability and where it occurs (line numbers, etc). You must extract this from the context.'),
});

export type SecurityPatchContextArgs = z.infer<typeof SecurityPatchContextArgsSchema>;

export async function getSecurityPatchContextMessages(args: SecurityPatchContextArgs) {
  const { vulnerability, filePath, pocFilePath, vulnerabilityContext } = args;
  const knowledge = await loadKnowledge(vulnerability);
  let fileContent = '';

  if (filePath) {
    try {
      fileContent = await fs.readFile(filePath, 'utf-8');
    } catch (e) {
      fileContent = `Error reading file: ${(e as Error).message}`;
    }
  }

  return {
    content: [
      {
        type: 'text',
        text: `## Patch Context:
**Knowledge Base:**
${knowledge}

**Context:**
${vulnerabilityContext || 'No specific context provided.'}

**Target File:**
${filePath || 'No file provided.'}

**PoC File:**
\`\`\`
${pocFilePath || 'No content available.'}
\`\`\`

**File Content:**
\`\`\`
${fileContent || 'No content available.'}
\`\`\`

**Next Steps:**
Invoke the security-patcher skill to apply the patch.
`,
      },
    ],
  };
}
