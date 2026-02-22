import { describe, it, expect, vi, beforeEach } from 'vitest';
import { GraphRetrievalService, ExpandedSearchResult } from './graph_retrieval_service.js';
import { SemanticSearchService, SemanticSearchResult } from './semantic_search.js';
import { GraphService } from '../graph_service.js';

describe('GraphRetrievalService', () => {
    let graphService: GraphService;
    let semanticSearchService: SemanticSearchService;
    let retrievalService: GraphRetrievalService;

    beforeEach(() => {
        graphService = new GraphService();
        
        // Mock SemanticSearchService
        semanticSearchService = {
            searchNodes: vi.fn(),
            // add other methods as needed, but we only use searchNodes here
        } as unknown as SemanticSearchService;

        retrievalService = new GraphRetrievalService(semanticSearchService, graphService);
    });

    it('should expand search results with 1-hop neighborhood', async () => {
        // Setup a mock graph: CallerA -> SeedNode -> CalleeB
        graphService.graph.nodes.set('CallerA', { id: 'CallerA', type: 'function', name: 'CallerA', startLine: 1, endLine: 5, documentation: '', codeSnippet: 'caller code' });
        graphService.graph.nodes.set('SeedNode', { id: 'SeedNode', type: 'function', name: 'SeedNode', startLine: 1, endLine: 5, documentation: '', codeSnippet: 'seed code' });
        graphService.graph.nodes.set('CalleeB', { id: 'CalleeB', type: 'function', name: 'CalleeB', startLine: 1, endLine: 5, documentation: '', codeSnippet: 'callee code', llmSummary: 'callee summary' });

        graphService.addEdge({ source: 'CallerA', target: 'SeedNode', type: 'call' });
        graphService.addEdge({ source: 'SeedNode', target: 'CalleeB', type: 'call' });

        // Mock semantic search returning just the SeedNode
        const mockSeedResult: SemanticSearchResult = {
            id: 'SeedNode',
            type: 'function',
            name: 'SeedNode',
            filePath: 'file.ts',
            codeSnippet: 'seed code',
            score: 0.95
        };
        (semanticSearchService.searchNodes as any).mockResolvedValue([mockSeedResult]);

        // Execute expansion
        const results = await retrievalService.searchWithGraphExpansion('query');

        expect(results.length).toBe(1);
        const expandedResult = results[0];
        
        expect(expandedResult.id).toBe('SeedNode');
        expect(expandedResult.expandedContext.calledBy.length).toBe(1);
        expect(expandedResult.expandedContext.calledBy[0].id).toBe('CallerA');
        
        expect(expandedResult.expandedContext.callsOutTo.length).toBe(1);
        expect(expandedResult.expandedContext.callsOutTo[0].id).toBe('CalleeB');
        
        // Ensure it prioritizes LLM summaries over code when available
        expect(expandedResult.expandedContext.callsOutTo[0].codeSnippet).toBe('callee summary');
    });
});
