import { describe, it, expect, vi, beforeEach } from 'vitest';
import { GraphSummarizer } from './graph_summarizer.js';
import { GraphService } from '../graph_service.js';
import { LlmProvider } from './llm_provider.js';
import { GraphNode } from '../models.js';

class MockLlmProvider implements LlmProvider {
    async generateText(prompt: string, jsonMode?: boolean): Promise<string> {
        return JSON.stringify({ "node1": "summary1" });
    }
}

describe('GraphSummarizer', () => {
    let graphService: GraphService;
    let llmProvider: LlmProvider;
    let summarizer: GraphSummarizer;

    beforeEach(() => {
        graphService = new GraphService();
        llmProvider = new MockLlmProvider();
        summarizer = new GraphSummarizer(graphService, llmProvider, 2);
    });

    it('should filter nodes based on type and minLines', () => {
        graphService.graph.nodes.set('n1', { id: 'n1', type: 'function', name: 'f1', startLine: 1, endLine: 5, documentation: '', codeSnippet: '' });
        graphService.graph.nodes.set('n2', { id: 'n2', type: 'variable', name: 'v1', startLine: 1, endLine: 10, documentation: '', codeSnippet: '' });
        graphService.graph.nodes.set('n3', { id: 'n3', type: 'method', name: 'm1', startLine: 1, endLine: 1, documentation: '', codeSnippet: '' }); // too short

        const filtered = summarizer.filterNodes();
        expect(filtered.length).toBe(1);
        expect(filtered[0].id).toBe('n1');
    });

    it('should topologically sort dependencies from leaves to roots', () => {
        // A -> B -> C
        // Processing order should be C, B, A
        graphService.graph.nodes.set('A', { id: 'A', type: 'function', name: 'A', startLine: 1, endLine: 10, documentation: '', codeSnippet: '' });
        graphService.graph.nodes.set('B', { id: 'B', type: 'function', name: 'B', startLine: 1, endLine: 10, documentation: '', codeSnippet: '' });
        graphService.graph.nodes.set('C', { id: 'C', type: 'function', name: 'C', startLine: 1, endLine: 10, documentation: '', codeSnippet: '' });

        graphService.addEdge({ source: 'A', target: 'B', type: 'call' });
        graphService.addEdge({ source: 'B', target: 'C', type: 'call' });

        const sccs = summarizer.tarjanTopologicalSort(summarizer.filterNodes());
        expect(sccs.length).toBe(3);
        expect(sccs[0][0].id).toBe('C');
        expect(sccs[1][0].id).toBe('B');
        expect(sccs[2][0].id).toBe('A');
    });

    it('should handle circular dependencies by grouping them into SCCs', () => {
        // A -> B -> C -> A (circular)
        // D -> A (D depends on the cycle)
        graphService.graph.nodes.set('A', { id: 'A', type: 'function', name: 'A', startLine: 1, endLine: 10, documentation: '', codeSnippet: '' });
        graphService.graph.nodes.set('B', { id: 'B', type: 'function', name: 'B', startLine: 1, endLine: 10, documentation: '', codeSnippet: '' });
        graphService.graph.nodes.set('C', { id: 'C', type: 'function', name: 'C', startLine: 1, endLine: 10, documentation: '', codeSnippet: '' });
        graphService.graph.nodes.set('D', { id: 'D', type: 'function', name: 'D', startLine: 1, endLine: 10, documentation: '', codeSnippet: '' });

        graphService.addEdge({ source: 'A', target: 'B', type: 'call' });
        graphService.addEdge({ source: 'B', target: 'C', type: 'call' });
        graphService.addEdge({ source: 'C', target: 'A', type: 'call' });
        graphService.addEdge({ source: 'D', target: 'A', type: 'call' });

        const sccs = summarizer.tarjanTopologicalSort(summarizer.filterNodes());
        expect(sccs.length).toBe(2);
        
        // Cycle should be first since D depends on it
        const cycleScc = sccs[0];
        expect(cycleScc.length).toBe(3);
        const cycleIds = cycleScc.map(n => n.id).sort();
        expect(cycleIds).toEqual(['A', 'B', 'C']);

        // D should be second
        expect(sccs[1].length).toBe(1);
        expect(sccs[1][0].id).toBe('D');
    });
});
