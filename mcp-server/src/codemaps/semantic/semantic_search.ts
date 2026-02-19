import { EmbeddingProvider, VectorDocument, SemanticQueryResult } from "./types.js";
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
  async indexGraph(): Promise<void> {
    console.log("[SemanticSearch] Starting full graph indexing...");
    const nodes = Array.from(this.graphService.graph.nodes.values());
    let processedCount = 0;

    for (const node of nodes) {
      // Skip purely structural nodes if they don't have meaning, 
      // but 'file' and 'module' might be useful context.
      // Let's index everything for now to handle "find file X".

      const textPayload = this.synthesizeNodePayload(node);
      
      try {
        const vector = await this.embeddingProvider.embed(textPayload);
        
        const doc: VectorDocument = {
          id: node.id,
          vector: vector,
          metadata: {
            name: node.name,
            type: node.type,
            filePath: node.id.split(':')[0]
          }
        };

        await this.vectorStore.add(doc);
        processedCount++;
        
        // Log progress every 50 nodes
        if (processedCount % 50 === 0) {
            console.log(`[SemanticSearch] Indexed ${processedCount}/${nodes.length} nodes...`);
        }
      } catch (error) {
        console.error(`[SemanticSearch] Failed to index node ${node.id}:`, error);
      }
    }

    await this.vectorStore.save();
    console.log(`[SemanticSearch] Finished indexing ${processedCount} nodes.`);
  }

  /**
   * Synthesizes a text payload that includes the node's code/doc
   * PLUS its structural neighborhood (incoming/outgoing edges).
   */
  private synthesizeNodePayload(node: GraphNode): string {
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

    // Construct the payload
    // We emphasize the "Neighborhood" first so the model sees connections immediately
    return `
Node ID: ${node.id}
Type: ${node.type}
File: ${node.id.split(':')[0]}
Called By (Incoming): ${calledBy || "None"}
Calls Out To (Outgoing): ${callsOutTo || "None"}

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
    const queryVector = await this.embeddingProvider.embed(query);
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
