import { EmbeddingProvider, VectorDocument, SemanticQueryResult, EmbeddingComponent } from "./types.js";
import * as crypto from 'crypto';
import { VectorStore } from "./vector_store.js";
import { GraphService } from "../graph_service.js"; // Assuming relative path correct
import { GraphNode } from "../models.js";
import { createChunker } from "code-chunk";
import * as fs from "fs/promises";
export interface SemanticSearchResult {
  id: string;
  type: string;
  name: string;
  filePath: string;
  codeSnippet: string;
  score: number;
}

/**
 * Orchestrates semantic search by indexing the graph into a vector store
 * and executing queries against it.
 */
export class SemanticSearchService {
  constructor(
    private graphService: GraphService,
    private vectorStore: VectorStore,
    private embeddingProvider: EmbeddingProvider
  ) {}

  /**
   * Re-indexes the entire graph into the vector store.
   * This involves:
   * 1. Iterating over all nodes.
   * 2. Synthesizing the "Text-Augmented Neighborhood" payload.
   * 3. Embedding the payload.
   * 4. Upserting to the VectorStore.
   * 5. Saving the VectorStore to disk.
   */
  async indexGraph(concurrencyLimit: number = 10, components: EmbeddingComponent[] = ['code', 'edges']): Promise<void> {
    console.log("[SemanticSearch] Starting incremental graph indexing...");
    const nodes = Array.from(this.graphService.graph.nodes.values());

    // 1. Prepare payload and hash for all nodes to identify what needs interaction
    const nodesToProcess: { node: GraphNode; payload: string; hash: string }[] = [];
    let totalEstimatedCost = 0;
    let skippedCount = 0;

    for (const node of nodes) {
      // 0. Filter out noisy low-level nodes and container nodes (files/modules)
      // We want to index atomic logic: classes, functions, methods, interfaces

      if (node.type === 'variable' || node.type === 'file' || node.type === 'module' || node.type === 'type_alias' || node.type === 'class') {
        continue;
      }

      const payload = this.synthesizeNodePayload(node, components);
      const hash = crypto.createHash('sha256').update(payload).digest('hex');

      // Check if node exists and hash matches
      const existingDoc = this.vectorStore.getDocument(node.id);
      if (existingDoc && existingDoc.metadata.contentHash === hash) {
        skippedCount++;
        continue; // Skip unchanged
      }

      nodesToProcess.push({ node, payload, hash });

      if (this.embeddingProvider.estimateCost) {
        totalEstimatedCost += this.embeddingProvider.estimateCost(payload);
      }
    }

    if (nodesToProcess.length === 0) {
      console.log(`[SemanticSearch] All ${nodes.length} nodes are up-to-date. No re-indexing needed.`);
      return;
    }

    console.log(`[SemanticSearch] Found ${nodesToProcess.length} nodes to index (${skippedCount} skipped).`);
    if (totalEstimatedCost > 0) {
      console.log(`[SemanticSearch] Estimated Embedding Cost: ~$${totalEstimatedCost.toFixed(6)} USD`);
    }

    let processedCount = 0;

    for (let i = 0; i < nodesToProcess.length; i += concurrencyLimit) {
      const batch = nodesToProcess.slice(i, i + concurrencyLimit);
      
      await Promise.all(batch.map(async ({ node, payload, hash }) => {
        try {
          const vector = await this.embeddingProvider.embed(payload);

          const doc: VectorDocument = {
            id: node.id,
            vector: vector,
            metadata: {
              name: node.name,
              type: node.type,
              filePath: node.id.split(':')[0],
              contentHash: hash,
              rawSnippet: node.codeSnippet || node.documentation || "(No code content)"
            }
          };

          await this.vectorStore.add(doc);
        } catch (error) {
          console.error(`[SemanticSearch] Failed to index node ${node.id}:`, error);
        }
      }));

      processedCount += batch.length;
      if (processedCount % 50 === 0 || processedCount === nodesToProcess.length) {
        console.log(`[SemanticSearch] Indexed ${processedCount}/${nodesToProcess.length} nodes...`);
      }
    }

    await this.vectorStore.save();
    console.log(`[SemanticSearch] Finished indexing ${processedCount} nodes.`);
  }

  /**
   * Synthesizes a text payload based on the requested EmbeddingComponents.
   */
  private synthesizeNodePayload(node: GraphNode, components: EmbeddingComponent[] = ['code', 'edges']): string {
    let payload = `Node ID: ${node.id}\nType: ${node.type}\nFile: ${node.id.split(':')[0]}\n`;

    if (components.includes('summary') && node.llmSummary) {
      payload += `\n[Summary]\n${node.llmSummary}\n`;
    }

    if (components.includes('edges')) {
      const incomingEdges = this.graphService.graph.inEdges.get(node.id) || [];
      const outgoingEdges = this.graphService.graph.edges.get(node.id) || [];

      // Map edges to readable file paths or node names
      const calledBy = incomingEdges
        .slice(0, 10) // Limit to 10 to fit in context
        .map(e => this.getNodeNameOrPath(e.source))
        .filter(x => x !== node.name) // Remove self-references if any
        .join(", ");

      const callsOutTo = outgoingEdges
        .slice(0, 10)
        .map(e => this.getNodeNameOrPath(e.target))
        .filter(x => x !== node.name)
        .join(", ");

      payload += `\n[Structural Context]\nCalled By (Incoming): ${calledBy || "None"}\nCalls Out To (Outgoing): ${callsOutTo || "None"}\n`;
    }

    if (components.includes('code')) {
      payload += `\n[Code Snippet]\n${node.codeSnippet || node.documentation || "(No code content)"}\n`;
    }

    return payload.trim();
  }

  /**
   * Semantically chunks and indexes files using the AST-aware code-chunk library.
   * Bypasses the standard graph builder and uses proper structural chunking.
   */
  async indexWithCodeChunk(files: string[], concurrencyLimit: number = 10): Promise<void> {
    console.log(`[SemanticSearch] Starting AST-aware code chunking for ${files.length} files...`);
    const chunker = createChunker({
      maxChunkSize: 1500,
      contextMode: "full",
      siblingDetail: "signatures",
    });

    const itemsToProcess: {
      id: string;
      name: string;
      type: string;
      filePath: string;
      rawSnippet: string;
      payload: string;
      hash: string;
    }[] = [];
    let totalEstimatedCost = 0;
    let skippedCount = 0;

    for (const file of files) {
      try {
        const source = await fs.readFile(file, 'utf8');
        let chunks;
        try {
          chunks = await chunker.chunk(file, source);
        } catch (e) {
          // Skip if language not supported or parse fails
          continue;
        }

        for (let i = 0; i < chunks.length; i++) {
          const chunk = chunks[i];
          const id = `${file}:${chunk.lineRange.start}-${chunk.lineRange.end}`;

          const primaryEntityName = chunk.context.entities.length > 0
            ? chunk.context.entities[0].name
            : `chunk_${i}`;

          const payload = chunk.contextualizedText;
          const hash = crypto.createHash('sha256').update(payload).digest('hex');

          // Check if node exists and hash matches
          const existingDoc = this.vectorStore.getDocument(id);
          if (existingDoc && existingDoc.metadata.contentHash === hash) {
            skippedCount++;
            continue; // Skip unchanged
          }

          itemsToProcess.push({
            id,
            name: primaryEntityName,
            type: 'semantic_chunk',
            filePath: file,
            rawSnippet: chunk.text,
            payload,
            hash
          });

          if (this.embeddingProvider.estimateCost) {
            totalEstimatedCost += this.embeddingProvider.estimateCost(payload);
          }
        }
      } catch (error) {
        console.error(`[SemanticSearch] Failed to read or chunk file ${file}:`, error);
      }
    }

    if (itemsToProcess.length === 0) {
      console.log(`[SemanticSearch] All chunks are up-to-date. No re-indexing needed.`);
      return;
    }

    console.log(`[SemanticSearch] Found ${itemsToProcess.length} chunks to index (${skippedCount} skipped).`);
    if (totalEstimatedCost > 0) {
      console.log(`[SemanticSearch] Estimated Embedding Cost: ~$${totalEstimatedCost.toFixed(6)} USD`);
    }

    let processedCount = 0;

    for (let i = 0; i < itemsToProcess.length; i += concurrencyLimit) {
      const batch = itemsToProcess.slice(i, i + concurrencyLimit);

      await Promise.all(batch.map(async (item) => {
        try {
          const vector = await this.embeddingProvider.embed(item.payload);

          const doc: VectorDocument = {
            id: item.id,
            vector: vector,
            metadata: {
              name: item.name,
              type: item.type,
              filePath: item.filePath,
              contentHash: item.hash,
              rawSnippet: item.rawSnippet
            }
          };

          await this.vectorStore.add(doc);
        } catch (error) {
          console.error(`[SemanticSearch] Failed to index chunk ${item.id}:`, error);
        }
      }));

      processedCount += batch.length;
      if (processedCount % 50 === 0 || processedCount === itemsToProcess.length) {
        console.log(`[SemanticSearch] Indexed ${processedCount}/${itemsToProcess.length} chunks...`);
      }
    }

    await this.vectorStore.save();
    console.log(`[SemanticSearch] Finished indexing ${processedCount} chunks.`);
  }

  private getNodeNameOrPath(nodeId: string): string {
    const node = this.graphService.graph.nodes.get(nodeId);
    if (node) return node.name;
    return nodeId.split(':')[0]; // Fallback to file path
  }

  /**
   * Semantically searches the vector store for documents matching the query.
   * Hydrates the results from the vector store metadata directly (no GraphService needed).
   */
  async searchNodes(query: string, limit: number = 5): Promise<SemanticSearchResult[]> {
    const queryVector = await this.embeddingProvider.embed(query, { taskType: 'SEARCH_QUERY' });
    const results = await this.vectorStore.query(queryVector, limit);

    // Hydrate results with actual data stored in VectorStore metadata
    const hydratedResults = results
      .map(res => {
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

    return hydratedResults;
  }
}
