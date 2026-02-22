import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SemanticRouter } from './semantic_router.js';
import { GraphService } from '../graph_service.js';
import { VectorStore } from './vector_store.js';
import { EmbeddingProvider } from './types.js';
import { LlmProvider } from './llm_provider.js';

class MockEmbeddingProvider implements EmbeddingProvider {
    async embed(text: string): Promise<number[]> {
        return [0.1, 0.2, 0.3];
    }
}

class MockLlmProvider implements LlmProvider {
    async generateText(prompt: string, jsonMode?: boolean): Promise<string> {
        return JSON.stringify({ "scopes": ["auth", "Authenticator"] });
    }
}

describe('SemanticRouter', () => {
    let graphService: GraphService;
    let vectorStore: VectorStore;
    let embeddingProvider: EmbeddingProvider;
    let llmProvider: LlmProvider;
    let router: SemanticRouter;

    beforeEach(() => {
        graphService = new GraphService();
        vectorStore = new VectorStore();
        embeddingProvider = new MockEmbeddingProvider();
        llmProvider = new MockLlmProvider();
        router = new SemanticRouter(graphService, vectorStore, embeddingProvider, llmProvider);
    });

    it('should generate an architecture map from graph nodes', () => {
        graphService.graph.nodes.set('auth/login.ts:Authenticator', { id: 'auth/login.ts:Authenticator', type: 'class', name: 'Authenticator', startLine: 1, endLine: 5, documentation: '', codeSnippet: '' });
        graphService.graph.nodes.set('auth/login.ts:loginFunc', { id: 'auth/login.ts:loginFunc', type: 'function', name: 'loginFunc', startLine: 1, endLine: 5, documentation: '', codeSnippet: '' });
        graphService.graph.nodes.set('ui/button.ts:PrimaryButton', { id: 'ui/button.ts:PrimaryButton', type: 'class', name: 'PrimaryButton', startLine: 1, endLine: 5, documentation: '', codeSnippet: '' });

        const archMap = router.generateArchitectureMap();
        expect(archMap).toContain('[File] auth/login.ts');
        expect(archMap).toContain('class: Authenticator');
        expect(archMap).toContain('function: loginFunc');
        expect(archMap).toContain('[File] ui/button.ts');
        expect(archMap).toContain('class: PrimaryButton');
    });

    it('should route and filter vector search based on LLM response', async () => {
        // Mock a vector store
        await vectorStore.add({ id: 'doc1', vector: [0.1, 0.2, 0.3], metadata: { type: 'method', filePath: 'auth/login.ts', name: 'Authenticator.verify' } });
        await vectorStore.add({ id: 'doc2', vector: [0.9, 0.8, 0.7], metadata: { type: 'method', filePath: 'ui/button.ts', name: 'PrimaryButton.click' } });
        await vectorStore.add({ id: 'doc3', vector: [0.1, 0.2, 0.3], metadata: { type: 'function', filePath: 'auth/utils.ts', name: 'helper' } }); // Matches "auth" scope

        const results = await router.routeAndSearch('query', 5);

        // The mock LLM returns scopes: ["auth", "Authenticator"]
        // doc1 matches both "auth" in filePath and "Authenticator" in name
        // doc2 matches neither
        // doc3 matches "auth" in filePath

        expect(results.length).toBe(2);
        const resultIds = results.map(r => r.id).sort();
        expect(resultIds).toEqual(['doc1', 'doc3']);
    });
});
