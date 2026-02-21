import { GraphService } from "../graph_service.js";
import { SemanticQueryResult } from "./types.js";
import { SemanticSearchService, SemanticSearchResult } from "./semantic_search.js";

export interface ExpandedSearchResult extends SemanticSearchResult {
    expandedContext: {
        calledBy: SemanticSearchResult[];
        callsOutTo: SemanticSearchResult[];
    };
}

/**
 * Service responsible for advanced retrieval paradigms, such as GraphRAG (Component Expansion).
 */
export class GraphRetrievalService {
    constructor(
        private semanticSearchService: SemanticSearchService,
        private graphService: GraphService
    ) {}

    /**
     * GraphRAG approach: 
     * 1. Finds initial "seed" nodes using standard semantic search.
     * 2. Expands the context window by injecting the code/summaries of their 1-hop neighbors.
     */
    async searchWithGraphExpansion(query: string, seedLimit: number = 3): Promise<ExpandedSearchResult[]> {
        // Step 1: Find seed nodes
        const seeds = await this.semanticSearchService.searchNodes(query, seedLimit);
        const expandedResults: ExpandedSearchResult[] = [];

        for (const seed of seeds) {
            const expandedResult: ExpandedSearchResult = {
                ...seed,
                expandedContext: {
                    calledBy: [],
                    callsOutTo: []
                }
            };

            // Step 2: Retrieve 1-hop neighborhood from GraphService
            const incomingEdges = this.graphService.graph.inEdges.get(seed.id) || [];
            const outgoingEdges = this.graphService.graph.edges.get(seed.id) || [];

            // We construct localized sub-results for the metadata
            for (const edge of incomingEdges) {
                if (edge.source === seed.id) continue; // Skip recursive self-calls
                const callerNode = this.graphService.graph.nodes.get(edge.source);
                if (callerNode) {
                    expandedResult.expandedContext.calledBy.push({
                        id: callerNode.id,
                        type: callerNode.type,
                        name: callerNode.name,
                        filePath: callerNode.id.split(':')[0],
                        codeSnippet: callerNode.llmSummary || callerNode.codeSnippet || "(No content)",
                        score: 0 // Contextual nodes don't have a direct query score
                    });
                }
            }

            for (const edge of outgoingEdges) {
                if (edge.target === seed.id) continue;
                const calleeNode = this.graphService.graph.nodes.get(edge.target);
                if (calleeNode) {
                    expandedResult.expandedContext.callsOutTo.push({
                        id: calleeNode.id,
                        type: calleeNode.type,
                        name: calleeNode.name,
                        filePath: calleeNode.id.split(':')[0],
                        codeSnippet: calleeNode.llmSummary || calleeNode.codeSnippet || "(No content)",
                        score: 0
                    });
                }
            }

            expandedResults.push(expandedResult);
        }

        return expandedResults;
    }
}
