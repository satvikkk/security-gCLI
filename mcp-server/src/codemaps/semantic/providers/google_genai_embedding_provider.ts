import { EmbeddingProvider } from "../types.js";
import { GoogleGenerativeAI, TaskType } from "@google/generative-ai";

/**
 * An embedding provider that uses Google's Generative AI SDK (@google/generative-ai).
 * Defaults to 'text-embedding-004'.
 */
export class GoogleGenAIEmbeddingProvider implements EmbeddingProvider {
    private client: GoogleGenerativeAI;
    private model: string;

    constructor(apiKey: string, model: string = "text-embedding-004") {
        this.client = new GoogleGenerativeAI(apiKey);
        this.model = model;
    }

    /**
     * Estimates cost in USD.
     * Based on average pricing of ~$0.000025 per character for text-embedding-004.
     */
    estimateCost(text: string): number {
        // Pricing varies, but this is a safe upper bound estimate for text-embedding-004
        return text.length * 0.000025;
    }

    async embed(text: string, options?: { taskType?: 'SEARCH_DOCUMENT' | 'SEARCH_QUERY' }): Promise<number[]> {
        const model = this.client.getGenerativeModel({ model: this.model });
        
        // Map generic options to Google TaskType
        // internal defaults: index = RETRIEVAL_DOCUMENT, query = RETRIEVAL_QUERY
        let googleTaskType = TaskType.RETRIEVAL_DOCUMENT;
        if (options?.taskType === 'SEARCH_QUERY') {
            googleTaskType = TaskType.RETRIEVAL_QUERY;
        }

        const result = await model.embedContent({
            content: { role: 'user', parts: [{ text }] },
            taskType: googleTaskType
        });

        if (!result.embedding || !result.embedding.values) {
            throw new Error(`Failed to generate embedding for text: ${text.slice(0, 50)}...`);
        }

        return result.embedding.values;
    }
}
