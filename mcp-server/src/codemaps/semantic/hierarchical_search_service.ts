import { SemanticSearchService, SemanticSearchResult } from "./semantic_search.js";
import { EmbeddingProvider } from "./types.js";
import { VectorStore } from "./vector_store.js";

/**
 * Service responsible for Hierarchical (Top-Down) Search.
 * It filters down the search space sequentially: Files -> Classes -> Methods.
 */
export class HierarchicalSearchService {
    constructor(
        private vectorStore: VectorStore,
        private embeddingProvider: EmbeddingProvider
    ) {}

    /**
     * Executes a top-down search to narrow context hierarchically.
     */
    async hierarchicalSearch(query: string, limitPerLevel: number = 2): Promise<SemanticSearchResult[]> {
        const queryVector = await this.embeddingProvider.embed(query, { taskType: 'SEARCH_QUERY' });
        
        // --- LEVEL 1: Search Files ---
        // We simulate level 1 by searching for module/file level documents.
        // If files are not explicitly indexed as nodes, we will fall back or simulate by finding top general hits 
        // and extracting their file paths to restrict Level 2.
        
        const allResults = await this.vectorStore.query(queryVector, limitPerLevel * 5); // Broad initial sweep
        
        // Extract unique file paths from the top broad results to form our "Level 1" domain
        const topFiles = Array.from(new Set(allResults.map(r => r.document.metadata.filePath))).slice(0, limitPerLevel);
        
        if (topFiles.length === 0) return [];

        console.log(`[HierarchicalSearch] Level 1 (Domain Filtering): Narrowed scope to files: ${topFiles.join(', ')}`);

        // --- LEVEL 2: Search Classes/Interfaces within those files ---
        const classLevelResults = allResults.filter(r => 
            topFiles.includes(r.document.metadata.filePath) && 
            ['class', 'interface'].includes(r.document.metadata.type)
        ).slice(0, limitPerLevel);

        const topClassNames = Array.from(new Set(classLevelResults.map(r => r.document.metadata.name)));

        // --- LEVEL 3: Search Methods/Functions within the narrowed domain ---
        // If we found specific classes, narrow to those classes.
        // Otherwise, simply look for methods inside the top files.
        const methodLevelDocs = this.vectorStore.searchFiltered(queryVector, limitPerLevel * 2, (doc) => {
            const isTargetFile = topFiles.includes(doc.metadata.filePath);
            const isTargetType = ['function', 'method'].includes(doc.metadata.type);
            
            // To properly filter by class, we'd need parentClass in metadata, but relying on the ID structure 
            // (e.g., file:ClassName.methodName) or just the file scoping works as a proxy for this PoC.
            if (topClassNames.length > 0) {
                const belongsToTopClass = topClassNames.some(cls => doc.metadata.name?.includes(cls) || (doc.id && doc.id.includes(cls)));
                return isTargetFile && isTargetType && belongsToTopClass;
            }
            return isTargetFile && isTargetType;
        });

        // Hydrate the final granular results
        return methodLevelDocs.map(res => {
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
