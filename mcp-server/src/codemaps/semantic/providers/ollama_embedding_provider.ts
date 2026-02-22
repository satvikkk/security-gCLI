/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { EmbeddingProvider } from '../types.js';

export class OllamaEmbeddingProvider implements EmbeddingProvider {
  constructor(
    private baseUrl: string = 'http://localhost:11434',
    private model: string = 'nomic-embed-text'
  ) { }

  async embed(text: string, options?: { taskType?: 'SEARCH_DOCUMENT' | 'SEARCH_QUERY' }): Promise<number[]> {
    try {
      const response = await fetch(`${this.baseUrl}/api/embeddings`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: this.model,
          prompt: text, // 'prompt' is the key for /api/embeddings
          options: {
            num_ctx: 8192 // Try to request a larger context window if possible
          }
        }),
      });

      if (!response.ok) {
        throw new Error(`Ollama API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json() as { embedding?: number[] };

      if (!data.embedding) {
        throw new Error(`Invalid response format from Ollama: ${JSON.stringify(data)}`);
      }

      return data.embedding;
    } catch (e: any) {
      console.error(`Failed to embed with Ollama (${this.model}):`, e);
      throw e;
    }
  }

  estimateCost(text: string): number {
    return 0; // Local inference is free (monetarily)
  }
}
