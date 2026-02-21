import { describe, it, expect, vi, beforeEach } from 'vitest';
import { HierarchicalSearchService } from './hierarchical_search_service.js';
import { VectorStore } from './vector_store.js';
import { EmbeddingProvider } from './types.js';

class MockEmbeddingProvider implements EmbeddingProvider {
    async embed(text: string): Promise<number[]> {
        return [0.1, 0.2, 0.3];
    }
}

describe('HierarchicalSearchService', () => {
    let vectorStore: VectorStore;
    let embeddingProvider: EmbeddingProvider;
    let hierarchicalService: HierarchicalSearchService;

    beforeEach(() => {
        vectorStore = new VectorStore();
        embeddingProvider = new MockEmbeddingProvider();
        hierarchicalService = new HierarchicalSearchService(vectorStore, embeddingProvider);
    });

    it('should iteratively narrow context from file -> class -> method', async () => {
        // Mock a vector store with a clear hierarchy
        
        // --- Files ---
        await vectorStore.add({ id: 'file1', vector: [0.1, 0.2, 0.3], metadata: { type: 'file', filePath: 'auth/login.ts', name: 'login.ts' } });
        await vectorStore.add({ id: 'file2', vector: [0.9, 0.8, 0.7], metadata: { type: 'file', filePath: 'ui/button.ts', name: 'button.ts' } });
        
        // --- Classes ---
        await vectorStore.add({ id: 'class1', vector: [0.1, 0.2, 0.3], metadata: { type: 'class', filePath: 'auth/login.ts', name: 'Authenticator' } });
        await vectorStore.add({ id: 'class2', vector: [0.9, 0.8, 0.7], metadata: { type: 'class', filePath: 'ui/button.ts', name: 'PrimaryButton' } });

        // --- Methods ---
        await vectorStore.add({ id: 'method1', vector: [0.1, 0.2, 0.3], metadata: { type: 'method', filePath: 'auth/login.ts', name: 'Authenticator.verify' } });
        await vectorStore.add({ id: 'method2', vector: [0.9, 0.8, 0.7], metadata: { type: 'method', filePath: 'ui/button.ts', name: 'PrimaryButton.click' } });
        await vectorStore.add({ id: 'method3', vector: [0.1, 0.2, 0.3], metadata: { type: 'function', filePath: 'auth/login.ts', name: 'helperFunction' } });

        // Let's pretend query vector is closely matched to [0.1, 0.2, 0.3]
        // This means broad hits are file1, class1, method1, method3
        const results = await hierarchicalService.hierarchicalSearch('query', 1);

        // Limit per level is 1. 
        // Level 1: top file is auth/login.ts
        // Level 2: top class in auth/login.ts is Authenticator
        // Level 3: Methods in auth/login.ts that belong to Authenticator -> method1

        expect(results.length).toBeGreaterThan(0);
        
        // Only method1 should surface if the hierarchical filtering works correctly
        expect(results.some(r => r.id === 'method1')).toBe(true);
        expect(results.some(r => r.id === 'method2')).toBe(false); // Wrong file/class
        expect(results.some(r => r.id === 'method3')).toBe(false); // Does not match class name filter
    });

    it('should return empty if no files match', async () => {
        const results = await hierarchicalService.hierarchicalSearch('query', 1);
        expect(results.length).toBe(0);
    });
});
