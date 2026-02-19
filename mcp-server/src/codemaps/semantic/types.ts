export interface EmbeddingProvider {
    /**
     * Generates a vector embedding for the given text.
     * @param text The input text to embed.
     * @returns A promise resolving to the vector (array of numbers).
     */
    embed(text: string): Promise<number[]>;
}

export interface VectorDocument {
    id: string;
    vector: number[];
    metadata: Record<string, any>;
}

export interface SemanticQueryResult {
    document: VectorDocument;
    score: number;
}
