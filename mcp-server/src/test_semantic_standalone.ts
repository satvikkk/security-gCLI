import { GraphService } from './codemaps/graph_service.js';
import { GraphBuilder } from './codemaps/graph_builder.js';
import { SemanticSearchService } from './codemaps/semantic/semantic_search.js';
import { VectorStore } from './codemaps/semantic/vector_store.js';
import { MockEmbeddingProvider } from './codemaps/semantic/providers/mock_embedding_provider.js';
import { GoogleGenAIEmbeddingProvider } from './codemaps/semantic/providers/google_genai_embedding_provider.js';
import { OllamaEmbeddingProvider } from './codemaps/semantic/providers/ollama_embedding_provider.js';
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

    const args = process.argv.slice(2);
    const forceReindex = args.includes('--force');
    const noEdges = args.includes('--no-edges');
    const useCodeChunk = args.includes('--use-code-chunk');

    let concurrency = 10;
    const concurrencyArg = args.find(a => a.startsWith('--concurrency='));
    if (concurrencyArg) {
        concurrency = parseInt(concurrencyArg.split('=')[1], 10) || 10;
    }

    const targetArg = args.find(a => !a.startsWith('--')) || 'src';
    const targetDir = path.resolve(process.cwd(), targetArg);
    const repoName = path.basename(targetDir);

    // Store standalone test vectors centrally, named by repo, to prevent dimension mismatches across models
    const storeDir = path.join(process.cwd(), '.gemini_security_tests');
    await fs.mkdir(storeDir, { recursive: true }).catch(() => { });
    const storePath = path.join(storeDir, `vectors_${repoName}.json`);

    if (forceReindex) {
        console.log(`🧹 --force flag detected. Removing existing embeddings at ${storePath}`);
        await fs.rm(storePath, { force: true }).catch(() => { });
    }

    console.log(`Target Dir: ${targetDir}`);
    console.log(`Vectors Store: ${storePath}`);

    // 1. Initialize Graph
    const graphService = new GraphService();
    const graphBuilder = new GraphBuilder(graphService);

    // 2. Build Graph (skip if using code-chunk)
    const files = await scan_dir(targetDir);
    console.log(`Found ${files.length} files.`);

    if (!useCodeChunk) {
        console.log(`Building graph manually...`);
        for (const file of files) {
            try {
                await graphBuilder.buildGraph(file);
            } catch (e: any) {
                // ignore errors
            }
        }
        console.log(`✅ Graph built! Nodes: ${graphService.graph.nodes.size}`);
    } else {
        console.log(`Skipping manual graph build in favor of code-chunk...`);
    }

    // 3. Initialize Semantic Components
    const vectorStore = new VectorStore(storePath);

    let embeddingProvider;
    if (process.env.GOOGLE_API_KEY) {
        console.log(`\nUsing Google GenAI Embedding Provider (text-embedding-004)...`);
        embeddingProvider = new GoogleGenAIEmbeddingProvider(process.env.GOOGLE_API_KEY);
    } else if (process.env.OLLAMA_HOST || process.env.USE_OLLAMA || process.env.OLLAMA_MODEL) {
        console.log(`\nUsing Ollama Embedding Provider...`);
        const host = process.env.OLLAMA_HOST || 'http://localhost:11434';
        const model = process.env.OLLAMA_MODEL || 'nomic-embed-text';
        embeddingProvider = new OllamaEmbeddingProvider(host, model);
    } else {
        console.log(`\nUsing Mock Embedding Provider (Deterministic)...`);
        embeddingProvider = new MockEmbeddingProvider();
    }

    const semanticService = new SemanticSearchService(graphService, vectorStore, embeddingProvider);

    // 4. Index
    console.log(`\nloading existing index...`);
    await vectorStore.load();
    const includeEdges = !noEdges;

    if (useCodeChunk) {
        console.log(`\nindexing files using code-chunk with concurrency ${concurrency}...`);
        await semanticService.indexWithCodeChunk(files, concurrency);
    } else {
        const components: ('code' | 'edges' | 'summary')[] = ['code'];
        if (includeEdges) {
            components.push('edges');
        }
        console.log(`\nindexing graph with concurrency ${concurrency}, components: ${components.join(',')}...`);
        await semanticService.indexGraph(concurrency, components);
    }

    // 5. Query
    const query = "function that translates one type of analytical definition into a different logic-based format to allow for unified evaluation. This process involves parsing complex expressions to extract data dependencies, normalizing syntax for compatibility with a target engine, and dynamically expanding specialized aggregate keywords into a series of functional calls based on the discovered dependencies. ";
    console.log(`\n🔎 Query: "${query}"`);

    const results = await semanticService.searchNodes(query, 30);

    console.log(`\nResults:`);
    results.forEach((node, i) => {
        console.log(`\n[${i + 1}] Score: ${node.score.toFixed(4)} | ID: ${node.id}`);
        console.log(`    Type: ${node.type}`);
        console.log(`    Snippet: ${(node.codeSnippet || '').slice(0, 100).replace(/\n/g, ' ')}...`);
    });
}

main().catch(console.error);
