import { EmbeddingProvider, VectorDocument, SemanticQueryResult } from "./types.js";
import * as crypto from 'crypto';
import { VectorStore } from "./vector_store.js";
import { GraphService } from "../graph_service.js"; // Assuming relative path correct
import { GraphNode } from "../models.js";

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
  async indexGraph(concurrencyLimit: number = 10, includeEdges: boolean = true): Promise<void> {
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

      const payload = this.synthesizeNodePayload(node, includeEdges);
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
              contentHash: hash
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
   * Synthesizes a text payload that includes the node's code/doc
   * PLUS its structural neighborhood (incoming/outgoing edges) conditionally.
   */
  private synthesizeNodePayload(node: GraphNode, includeEdges: boolean = true): string {
    let edgesInfo = "";

    if (includeEdges) {
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

      edgesInfo = `\nCalled By (Incoming): ${calledBy || "None"}\nCalls Out To (Outgoing): ${callsOutTo || "None"}`;
    }

    // Construct the payload
    // We emphasize the "Neighborhood" first so the model sees connections immediately
    return `
Node ID: ${node.id}
Type: ${node.type}
File: ${node.id.split(':')[0]}${edgesInfo}

Snippet:
${node.codeSnippet || node.documentation || "(No code content)"}
`.trim();
  }

  private getNodeNameOrPath(nodeId: string): string {
    const node = this.graphService.graph.nodes.get(nodeId);
    if (node) return node.name;
    return nodeId.split(':')[0]; // Fallback to file path
  }

  /**
   * Semantically searches the graph for nodes matching the query.
   */
  async searchNodes(query: string, limit: number = 5): Promise<(GraphNode & { score: number })[]> {
    const queryVector = await this.embeddingProvider.embed(query, { taskType: 'SEARCH_QUERY' });
    const results = await this.vectorStore.query(queryVector, limit);

    // Hydrate results with actual GraphNode data
    const hydratedResults = results
      .map(res => {
        const node = this.graphService.graph.nodes.get(res.document.id);
        if (!node) return null;
        return {
          ...node,
          score: res.score
        };
      })
      .filter((n): n is (GraphNode & { score: number }) => n !== null);

    return hydratedResults;
  }
}
