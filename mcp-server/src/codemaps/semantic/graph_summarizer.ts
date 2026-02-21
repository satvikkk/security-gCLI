import { GraphService } from "../graph_service.js";
import { GraphNode } from "../models.js";
import { LlmProvider } from "./llm_provider.js";

/**
 * Summarizes the AST Graph by querying an LLM in a topological, bottom-up order,
 * ensuring callers have context from their callees.
 */
export class GraphSummarizer {
  constructor(
    private graphService: GraphService,
    private llmProvider: LlmProvider,
    private minLines: number = 5
  ) { }

  /**
   * Filters nodes that are candidates for summarization.
   * Targets non-trivial functions, methods, and classes.
   */
  filterNodes(): GraphNode[] {
    const nodes = Array.from(this.graphService.graph.nodes.values());
    return nodes.filter(node => {
      if (!['function', 'method', 'class'].includes(node.type)) return false;

      const lineCount = node.endLine - node.startLine + 1;
      if (lineCount < this.minLines) return false;

      return true;
    });
  }

  /**
   * Implements Tarjan's Strongly Connected Components algorithm.
   * Returns an array of SCCs (each an array of GraphNodes).
   * The array is topologically sorted from leaves to roots, meaning SCCs with no
   * dependencies (or whose dependencies have already been processed) appear first.
   */
  tarjanTopologicalSort(nodes: GraphNode[]): GraphNode[][] {
    const indexMap = new Map<string, number>();
    const lowLinkMap = new Map<string, number>();
    const onStack = new Set<string>();
    const stack: GraphNode[] = [];
    let index = 0;
    const sccs: GraphNode[][] = [];

    const nodeMap = new Map<string, GraphNode>();
    for (const n of nodes) nodeMap.set(n.id, n);

    const strongConnect = (v: GraphNode) => {
      indexMap.set(v.id, index);
      lowLinkMap.set(v.id, index);
      index++;
      stack.push(v);
      onStack.add(v.id);

      const outgoingEdges = this.graphService.graph.edges.get(v.id) || [];
      for (const edge of outgoingEdges) {
        const w = nodeMap.get(edge.target);
        if (!w) continue; // Skip targets not in our filtered set

        if (!indexMap.has(w.id)) {
          strongConnect(w);
          lowLinkMap.set(v.id, Math.min(lowLinkMap.get(v.id)!, lowLinkMap.get(w.id)!));
        } else if (onStack.has(w.id)) {
          lowLinkMap.set(v.id, Math.min(lowLinkMap.get(v.id)!, indexMap.get(w.id)!));
        }
      }

      if (lowLinkMap.get(v.id) === indexMap.get(v.id)) {
        const scc: GraphNode[] = [];
        let curr: GraphNode;
        do {
          curr = stack.pop()!;
          onStack.delete(curr.id);
          scc.push(curr);
        } while (curr.id !== v.id);
        sccs.push(scc);
      }
    };

    for (const v of nodes) {
      if (!indexMap.has(v.id)) {
        strongConnect(v);
      }
    }

    return sccs;
  }

  /**
   * Executes the topological summarization process.
   */
  async summarize(batchSize: number = 10): Promise<void> {
    const filteredNodes = this.filterNodes();
    const sccs = this.tarjanTopologicalSort(filteredNodes);

    console.log(`[GraphSummarizer] Found ${filteredNodes.length} nodes to summarize across ${sccs.length} Strong Components.`);

    // Process sequentially to ensure dependencies are summarized before their parents
    for (const scc of sccs) {
      // Further batch within the SCC to avoid massive prompts
      for (let i = 0; i < scc.length; i += batchSize) {
        const batch = scc.slice(i, i + batchSize);
        // Filter out already summarized nodes if any in-memory caching exists
        const toProcess = batch.filter(n => !n.llmSummary);
        if (toProcess.length > 0) {
          await this.summarizeBatch(toProcess);
        }
      }
    }

    console.log(`[GraphSummarizer] Finished topological summarization.`);
  }

  private async summarizeBatch(batch: GraphNode[]): Promise<void> {
    const promptParts: string[] = [];

    for (const node of batch) {
      const outgoingEdges = this.graphService.graph.edges.get(node.id) || [];
      const depSummaries: string[] = [];

      for (const edge of outgoingEdges) {
        const callee = this.graphService.graph.nodes.get(edge.target);
        if (callee && callee.llmSummary) {
          depSummaries.push(`- ${callee.name || callee.id}: ${callee.llmSummary}`);
        }
      }

      let nodePrompt = `ID: ${node.id}\nType: ${node.type}\nName: ${node.name}\n`;
      if (depSummaries.length > 0) {
        nodePrompt += `Dependencies Context:\n${depSummaries.join('\n')}\n`;
      }
      nodePrompt += `Code:\n${node.codeSnippet || node.documentation || "(No code)"}\n---`;
      promptParts.push(nodePrompt);
    }

    const systemInstruction = `You are an expert software engineer.
Summarize the purpose and logic of the provided code blocks.
If external dependency context is provided, incorporate what those dependencies do into your understanding of the logic.
Return ONLY a valid JSON object mapping the ID to a clear, concise 1-2 sentence summary.
Format: { "node_id_1": "summary text...", "node_id_2": "summary text..." }`;

    const finalPrompt = `${systemInstruction}\n\n${promptParts.join('\n')}`;

    try {
      const response = await this.llmProvider.generateText(finalPrompt, true);
      // Defensively extract JSON
      const contentMatcher = response.match(/\{[\s\S]*\}/);
      const jsonStr = contentMatcher ? contentMatcher[0] : response;
      const summaries = JSON.parse(jsonStr);

      let successCount = 0;
      for (const node of batch) {
        if (summaries[node.id]) {
          node.llmSummary = summaries[node.id];
          successCount++;
        }
      }
      console.log(`[GraphSummarizer] Summarized ${successCount}/${batch.length} nodes in batch.`);
    } catch (error) {
      console.error(`[GraphSummarizer] Failed to summarize batch:`, error);
    }
  }
}
