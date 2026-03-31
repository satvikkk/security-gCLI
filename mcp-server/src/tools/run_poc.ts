/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { z } from 'zod';
import { runPoc } from '../poc.js';

export const RUN_POC_TOOL_NAME = 'run_poc';
export const RUN_POC_TOOL_DESCRIPTION = 'Runs the generated PoC code.';

export const RunPocArgsSchema = z.object({
  filePath: z.string().describe('The absolute path to the PoC file to run.'),
});

export type RunPocArgs = z.infer<typeof RunPocArgsSchema>;

export async function getRunPocMessages(input: RunPocArgs) {
  const result = await runPoc(input);

  if (result.isSecurityError) {
    return {
      content: [
        {
          type: 'text',
          text: `Security Error: ${result.error}`,
        },
      ],
      isError: true,
    };
  }

  let text = `## PoC Execution\n`;
  if (result.error) {
    text += `**Error:** ${result.error}\n\n`;
  }
  text += `#### stdout\n\`\`\`\n${result.stdout}\n\`\`\`\n\n#### stderr\n\`\`\`\n${result.stderr}\n\`\`\`\n`;

  return {
    content: [
      {
        type: 'text',
        text,
      },
    ],
  };
}
