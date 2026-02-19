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

    async embed(text: string): Promise<number[]> {
        const model = this.client.getGenerativeModel({ model: this.model });
        
        // Task type explicit for better retrieval performance
        const result = await model.embedContent({
            content: { role: 'user', parts: [{ text }] },
            taskType: TaskType.RETRIEVAL_DOCUMENT
        });

        if (!result.embedding || !result.embedding.values) {
            throw new Error(`Failed to generate embedding for text: ${text.slice(0, 50)}...`);
        }

        return result.embedding.values;
    }
}
