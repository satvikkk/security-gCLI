import { GraphService } from './codemaps/graph_service.js';
import { GraphBuilder } from './codemaps/graph_builder.js';
import { SemanticSearchService } from './codemaps/semantic/semantic_search.js';
import { VectorStore } from './codemaps/semantic/vector_store.js';
import { MockEmbeddingProvider } from './codemaps/semantic/providers/mock_embedding_provider.js';
import { GoogleGenAIEmbeddingProvider } from './codemaps/semantic/providers/google_genai_embedding_provider.js';
import * as path from 'path';
import { promises as fs } from 'fs';
import * as os from 'os';

// Simple recursive directory scanner
async function scan_dir(dir_path: string): Promise<string[]> {
    const exts = ['.py', '.js', '.ts', '.tsx', '.go'];
    const excludes = ['.git', 'node_modules', 'dist', 'build', '.gemini_security'];
    const files: string[] = [];

    async function scan(currentPath: string) {
        const entries = await fs.readdir(currentPath, { withFileTypes: true });
        for (const entry of entries) {
            if (excludes.includes(entry.name)) {
                continue;
            }
            const fullPath = path.join(currentPath, entry.name);
            if (entry.isDirectory()) {
                await scan(fullPath);
            } else if (exts.some(ext => entry.name.endsWith(ext))) {
                files.push(fullPath);
            }
        }
    }

    try {
        await scan(dir_path);
    } catch (e) {
        console.error(`Failed to scan dir: ${dir_path}`, e);
    }
    return files;
}

async function main() {
    console.log(`\n================================`);
    console.log(`🧠 STANDALONE SEMANTIC SEARCH TEST   `);
    console.log(`================================`);

    const targetDir = path.resolve(process.cwd(), 'src'); // Scan src by default
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'semantic-test-'));
    const storePath = path.join(tmpDir, 'vectors.json');

    console.log(`Target Dir: ${targetDir}`);
    console.log(`Vectors Store: ${storePath}`);

    // 1. Initialize Graph
    const graphService = new GraphService();
    const graphBuilder = new GraphBuilder(graphService);

    // 2. Build Graph
    const files = await scan_dir(targetDir);
    console.log(`Found ${files.length} files. Building graph...`);

    for (const file of files) {
        try {
            await graphBuilder.buildGraph(file);
        } catch (e: any) {
            // ignore errors
        }
    }
    console.log(`✅ Graph built! Nodes: ${graphService.graph.nodes.size}`);

    // 3. Initialize Semantic Components
    const vectorStore = new VectorStore(storePath);

    let embeddingProvider;
    if (process.env.GOOGLE_API_KEY) {
        console.log(`\nUsing Google GenAI Embedding Provider (text-embedding-004)...`);
        embeddingProvider = new GoogleGenAIEmbeddingProvider(process.env.GOOGLE_API_KEY);
    } else {
        console.log(`\nUsing Mock Embedding Provider (Deterministic)...`);
        embeddingProvider = new MockEmbeddingProvider();
    }

    const semanticService = new SemanticSearchService(graphService, vectorStore, embeddingProvider);

    // 4. Index
    console.log(`\nindexing graph...`);
    await semanticService.indexGraph();

    // 5. Query
    const query = "find filesystem scanning logic";
    console.log(`\n🔎 Query: "${query}"`);

    const results = await semanticService.searchNodes(query, 3);

    console.log(`\nResults:`);
    results.forEach((node, i) => {
        console.log(`\n[${i + 1}] Score: ${node.score.toFixed(4)} | ID: ${node.id}`);
        console.log(`    Type: ${node.type}`);
        console.log(`    Snippet: ${(node.codeSnippet || '').slice(0, 100).replace(/\n/g, ' ')}...`);
    });

    // Cleanup
    await fs.rm(tmpDir, { recursive: true, force: true });
}

main().catch(console.error);
