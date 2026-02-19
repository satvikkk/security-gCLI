import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SemanticSearchService } from './semantic_search.js';
import { GraphService } from '../graph_service.js';
import { VectorStore } from './vector_store.js';
import { MockEmbeddingProvider } from './providers/mock_embedding_provider.js';
import { GraphNode, GraphEdge } from '../models.js';

// Mocks
class MockVectorStore extends VectorStore {
    public addedDocs: any[] = [];
    async add(doc: any) {
        this.addedDocs.push(doc);
    }
    async save() { }
    async query(vector: number[], k: number) {
        return [] as any[];
    }
}

describe('Semantic Search', () => {

    describe('MockEmbeddingProvider', () => {
        it('should return deterministic vectors', async () => {
            const provider = new MockEmbeddingProvider(3);
            const vec1 = await provider.embed('hello');
            const vec2 = await provider.embed('hello');
            const vec3 = await provider.embed('world');

            expect(vec1).toEqual(vec2);
            expect(vec1).not.toEqual(vec3);
            expect(vec1.length).toBe(3);
        });
    });

    describe('SemanticSearchService', () => {
        let graphService: GraphService;
        let vectorStore: MockVectorStore;
        let embeddingProvider: MockEmbeddingProvider;
        let service: SemanticSearchService;

        beforeEach(() => {
            graphService = new GraphService();
            vectorStore = new MockVectorStore('test-path');
            embeddingProvider = new MockEmbeddingProvider(3);
            service = new SemanticSearchService(graphService, vectorStore, embeddingProvider);
        });

        it('should synthesize neighborhood context during indexing', async () => {
            // Setup Graph: File A -> File B
            const nodeA: GraphNode = {
                id: 'fileA.ts:funcA', type: 'function', name: 'funcA',
                startLine: 1, endLine: 5, codeSnippet: 'function A(){}', documentation: ''
            };
            const nodeB: GraphNode = {
                id: 'fileB.ts:funcB', type: 'function', name: 'funcB',
                startLine: 1, endLine: 5, codeSnippet: 'function B(){}', documentation: ''
            };

            graphService.addNode(nodeA);
            graphService.addNode(nodeB);

            // Edge: A calls B
            graphService.addEdge({ source: nodeA.id, target: nodeB.id, type: 'calls' });

            // Spy on embedding provider to capture the text it receives
            const embedSpy = vi.spyOn(embeddingProvider, 'embed');

            await service.indexGraph();

            expect(vectorStore.addedDocs.length).toBe(2);

            // Check what text was sent to be embedded for Node A
            // Node A calls Node B, so its payload should mention "funcB" or "fileB.ts" in 'Calls Out To'
            const callArgsA = embedSpy.mock.calls.find(call => call[0].includes('Node ID: fileA.ts:funcA'));
            expect(callArgsA).toBeDefined();
            const textA = callArgsA![0];

            expect(textA).toContain('Calls Out To (Outgoing): funcB');
            expect(textA).toContain('Snippet:\nfunction A(){}');

            // Check Node B payload
            // Node B is called by Node A, so payload should mention "funcA" in 'Called By'
            const callArgsB = embedSpy.mock.calls.find(call => call[0].includes('Node ID: fileB.ts:funcB'));
            expect(callArgsB).toBeDefined();
            const textB = callArgsB![0];

            expect(textB).toContain('Called By (Incoming): funcA');
        });

        it('should hydrate search results with graph nodes', async () => {
            const nodeA: GraphNode = {
                id: 'test.ts:target', type: 'function', name: 'target',
                startLine: 10, endLine: 20, codeSnippet: 'target()', documentation: ''
            };
            graphService.addNode(nodeA);

            // Mock vector store query to return this node
            vi.spyOn(vectorStore, 'query').mockResolvedValue([
                { document: { id: nodeA.id, vector: [1, 1, 1], metadata: {} }, score: 0.95 }
            ]);

            const results = await service.searchNodes('find target');

            expect(results.length).toBe(1);
            expect(results[0].id).toBe(nodeA.id);
            expect(results[0].score).toBe(0.95);
            expect(results[0].codeSnippet).toBe('target()');
        });
    });
});
