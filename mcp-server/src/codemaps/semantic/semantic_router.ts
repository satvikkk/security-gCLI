import { GraphService } from "../graph_service.js";
import { VectorStore } from "./vector_store.js";
import { EmbeddingProvider } from "./types.js";
import { SemanticSearchResult } from "./semantic_search.js";
import { LlmProvider } from "./llm_provider.js";

interface TargetScopes {
    scopes: string[];
}

/**
 * Service responsible for Structural Agentic Routing.
 * Uses an architecture map and an LLM to decide which scopes to search.
 */
export class SemanticRouter {
    constructor(
        private graphService: GraphService,
        private vectorStore: VectorStore,
        private embeddingProvider: EmbeddingProvider,
        private llmProvider: LlmProvider
    ) {}

    /**
     * Generates a structural map of the codebase from the graph.
     * Groups classes and functions by file path.
     */
    generateArchitectureMap(): string {
        const fileMap = new Map<string, string[]>();

        for (const [id, node] of this.graphService.graph.nodes.entries()) {
            if (!['class', 'interface', 'function', 'test'].includes(node.type)) {
                continue;
            }

            const filePath = node.id.split(':')[0];
            if (!fileMap.has(filePath)) {
                fileMap.set(filePath, []);
            }
            fileMap.get(filePath)!.push(`${node.type}: ${node.name}`);
        }

        let mapString = "";
        for (const [filePath, symbols] of fileMap.entries()) {
            mapString += `\n[File] ${filePath}\n`;
            symbols.forEach(sym => mapString += `  - ${sym}\n`);
        }

        return mapString.trim();
    }

    /**
     * Asks an LLM to route the query based on the architecture map,
     * then executes a filtered vector search within the chosen scopes.
     */
    async routeAndSearch(query: string, limit: number = 5): Promise<SemanticSearchResult[]> {
        const architectureMap = this.generateArchitectureMap();

        const prompt = `You are an expert software architect routing a search query.
User Query: "${query}"

Below is a structural map of the codebase:
${architectureMap}

Based on the codebase map, which file paths or classes are most likely to contain the answer to the user's query?
Return ONLY a valid JSON object containing an array of target scopes. A scope can be a file path (e.g., "src/index.ts") or a class name.

Format:
{
  "scopes": ["target_scope_1", "target_scope_2"]
}`;

        let scopes: string[] = [];
        try {
            const response = await this.llmProvider.generateText(prompt, true);
            const contentMatcher = response.match(/\{[\s\S]*\}/);
            const jsonStr = contentMatcher ? contentMatcher[0] : response;
            const data: TargetScopes = JSON.parse(jsonStr);
            scopes = data.scopes || [];
            console.log(`[SemanticRouter] LLM chose scopes: ${scopes.join(', ')}`);
        } catch (e) {
            console.error("[SemanticRouter] Failed to parse scopes from LLM, falling back to global search.", e);
        }

        const queryVector = await this.embeddingProvider.embed(query, { taskType: 'SEARCH_QUERY' });

        const resultsDocs = this.vectorStore.searchFiltered(queryVector, limit, (doc) => {
            if (scopes.length === 0) return true; // Global search fallback
            
            // Check if document matches any of the LLM chosen scopes
            return scopes.some(scope => {
                const isFileMatch = doc.metadata.filePath && doc.metadata.filePath.includes(scope);
                const isNameMatch = doc.metadata.name && doc.metadata.name.includes(scope);
                return isFileMatch || isNameMatch;
            });
        });

        return resultsDocs.map(res => {
            const doc = res.document;
            return {
                id: doc.id,
                type: doc.metadata.type || 'unknown',
                name: doc.metadata.name || doc.id,
                filePath: doc.metadata.filePath || doc.id.split(':')[0],
                codeSnippet: doc.metadata.rawSnippet || "(Snippet missing from index)",
                score: res.score
            };
        });
    }
}
