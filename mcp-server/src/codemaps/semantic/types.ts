export type EmbeddingComponent = 'code' | 'edges' | 'summary';

export interface EmbeddingProvider {
    /**
     * Generates a vector embedding for the given text.
     * @param text The input text to embed.
     * @returns A promise resolving to the vector (array of numbers).
     */
    embed(text: string, options?: { taskType?: 'SEARCH_DOCUMENT' | 'SEARCH_QUERY' }): Promise<number[]>;

    /**
     * Estimated cost in USD for embedding the given text.
     * Optional.
     */
    estimateCost?(text: string): number;
}

export interface VectorDocument {
    id: string;
    vector: number[];
    metadata: {
        contentHash?: string; // SHA-256 hash for incremental indexing
        [key: string]: any;
    };
}

export interface SemanticQueryResult {
    document: VectorDocument;
    score: number;
}
