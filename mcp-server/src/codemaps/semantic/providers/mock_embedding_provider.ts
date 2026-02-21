import { EmbeddingProvider } from "../types.js";

/**
 * A mock embedding provider that generates deterministic pseudo-random vectors based on text length.
 * Useful for testing the semantic search pipeline without external API calls.
 */
export class MockEmbeddingProvider implements EmbeddingProvider {
    private dimensions: number;

    constructor(dimensions: number = 1536) {
        this.dimensions = dimensions;
    }

    estimateCost(text: string): number {
        return 0; // Mock is free
    }

    async embed(text: string): Promise<number[]> {
        // Deterministic pseudo-random vector based on string hash
        let hash = 0;
        for (let i = 0; i < text.length; i++) {
            const char = text.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32bit integer
        }

        const vector: number[] = [];
        for (let i = 0; i < this.dimensions; i++) {
            // Use a simple seeded random generator based on the hash + dimension index
            const val = Math.sin(hash + i) * 10000;
            vector.push(val - Math.floor(val)); // Normalized 0-1 (roughly)
        }
        return vector;
    }
}
