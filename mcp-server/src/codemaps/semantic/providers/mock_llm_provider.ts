import { LlmProvider } from "../llm_provider.js";

/**
 * A mock LLM provider for testing and development without requiring API tokens.
 * Returns deterministic dummy responses.
 */
export class MockLlmProvider implements LlmProvider {
    async generateText(prompt: string, jsonMode: boolean = false): Promise<string> {
        // If it looks like a request from SemanticRouter
        if (prompt.includes("Return ONLY a valid JSON object containing an array of target scopes")) {
            return JSON.stringify({ scopes: ["auth", "google_genai", "graph_retrieval_service"] });
        }
        
        // If it looks like a request from GraphSummarizer
        if (prompt.includes("Format: { \"node_id_1\": \"summary text...\"")) {
            // Extract IDs from prompt to generate mock summaries
            const ids = prompt.match(/ID: (.*?)\n/g)?.map(m => m.replace('ID: ', '').trim()) || [];
            const result: Record<string, string> = {};
            for (const id of ids) {
                result[id] = `[MOCK SUMMARY] This is a mocked summary for node ${id.split(':').pop()}.`;
            }
            return JSON.stringify(result);
        }

        // Default mock response
        if (jsonMode) {
            return JSON.stringify({ mock: "This is a mocked JSON response." });
        }
        return "[MOCK RESPONSE] This is a mocked text response.";
    }
}
