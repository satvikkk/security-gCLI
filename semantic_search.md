# Bridging the Intent-to-Structure Gap: Semantic Search in CodeMaps

## The Motivation: Why We Need Semantic Search
The core value proposition of `codemaps` is providing autonomous LLM agents with instantaneous, perfectly accurate structural intelligence through an "Agent's Compiler" (see `new_features.md`).

However, there is a fundamental gap in this workflow: **The Cold Start Problem.**

All structural graph queries (e.g., impact analysis, blast radius, feature tracing) natively require a precise starting coordinate—a specific `node_id` (like `src/auth/service.ts:validateToken`).
When an agent is given a natural language task like *"Fix the issue where enterprise users cannot bypass the 2FA prompt"*, it does not know which `node_id` to query. 

Without semantic search, the agent must resort to bruteforce, token-heavy text searches (e.g., `grep -rn "2FA" .`) to guess the starting point, completely undermining the efficiency of the graph. We need a semantic bridge to translate **Natural Language Intent** -> **Structural Root Node**.

---

## The Standard Approach: Standard RAG (Retrieval-Augmented Generation)
The industry standard for solving this is creating code embeddings:
1. Parse the repository into text chunks (usually by function or class).
2. Use an embedding model (e.g., `text-embedding-3-small`) to convert the raw text into dense mathematical vectors.
3. Store these vectors in a Vector Database (like Pinecone, Milvus, or local ChromaDB).
4. When the agent receives a task, embed the task prompt and retrieve the top-*k* nodes with the highest cosine similarity.

**The Fatal Flaw of Standard RAG for Code:**
Standard vector embeddings are purely semantic; they ignore architecture. If an agent searches for "database execution," a generic `execute()` helper function in a random string-parsing utility file will look mathematically identical to the actual `execute()` function inside the core `db.ts` transaction ledger. Vector search only sees the text, not the neighborhood, causing the agent to start its structural queries in the wrong part of the codebase.

---

## The CodeMaps Advantage: Graph-Augmented Retrieval

Because we already possess a meticulously parsed Directed Graph of the codebase via the `GraphService`, we can inject **spatial and structural awareness** directly into the semantic search pipeline. 

We can leverage the structural topology using three progressive strategies:

### Strategy 1: "Poor Man's Graph RAG" (Text-Augmented Neighborhoods)
**Status:** Highly Recommended / Immediate Implementation
**Approach:** 
We continue to use standard text embeddings, but we fundamentally alter the *payload* being embedded. When `GraphService` registers a node, we do not just embed its raw snippet. We synthesize a document that injects the node's structural neighborhood directly into the text header.

**Example Embedding Text:**
```text
Node: process_transaction
Path: src/billing/ledger.ts
Called By (incoming): api/billing_router.ts, cron/monthly_invoice.ts
Calls (outgoing): stripe/api.ts, db/ledger.ts

function process_transaction(req) { // raw code snippet here }
```
**Why it works:** By explicitly forcing upstream/downstream structural dependencies into the embedded text, the vector model naturally learns that `process_transaction` is heavily related to "Stripe" and "Billing", even if those words aren't inside the function body itself!

### Strategy 2: Heuristic Graph Re-ranking (Centrality Boosting)
**Status:** Recommended / Second Iteration Pass
**Approach:** 
1. **Pass 1:** Execute a standard/cheap vector search to retrieve the Top 50 semantic matches for a natural language task.
2. **Pass 2:** Intersect those results with the `codemaps` structure and re-rank them using **In-Degree Centrality** or **PageRank**.
**Why it works:** This solves the common "LLM gets distracted by test suites" problem. If the search returns a mock testing file with an in-degree of 0, and a core Service interface with an in-degree of 45, the graph ranking exponentially boosts the Service interface to the top of the vector results. High-gravity structural nodes are prioritized over isolated semantic matches.

### Strategy 3: Native Graph Embeddings (GraphSAGE / Node2Vec)
**Status:** Long-term R&D / Stretch Goal
**Approach:** 
Instead of relying strictly on LLM text-transformers, we implement a Graph Neural Network (GNN) to mathematically encode the topology of the codebase into the vector space.
**Why it works:** Nodes that share similar structural footprints (e.g., two distinct controllers that both speak to the same database proxy and route to the same UI layers) are grouped together mathematically, regardless of their text. We combine this structural vector (`Node2Vec`) with the semantic text vector to achieve absolute conceptual accuracy.

---

## Implementation Guide for Strategy 1 (Text-Augmented Neighborhoods)

For the coding agent taking this up, here is the exact step-by-step implementation plan to add Semantic Search to the `codemaps` MCP Server:

### Phase 1: Storage and Embedding Preparation
1.  **Add Dependencies:** Add a lightweight local vector store (e.g., `sqlite-vss`, `chromadb`, or a simple memory-based cosine similarity array if dependencies must be kept minimal) and an embedding client (e.g., `@google/genai` or `openai` depending on the user's preferred LLM provider) to `mcp-server/package.json`.
2.  **Initialize Vector Store:** Create a `VectorService` class (similar to `GraphService`) that initializes the local DB upon server start. It should expose methods for `upsert_embedding(id, vector)` and `query_similar(vector, k=5)`.

### Phase 2: Neighborhood Synthesis
1.  **Intercept Graph Building:** Inside `GraphBuilder` (or wherever nodes are finalized), after all parsing is complete and structural edges are established, iterate over every node in the graph.
2.  **Synthesize Meta-Text:** For each node, generate the "Text-Augmented Neighborhood" payload.
    *   Find all *incoming* edges (e.g., who calls this node). Map these back to human-readable source file paths.
    *   Find all *outgoing* edges (e.g., who this node calls). Map these back to target file paths.
    *   Combine this into a strictly formatted string:
        ```text
        Node ID: <node.id>
        Type: <node.type>
        File: <file path>
        Called By: <comma-separated list of incoming dependency files>
        Calls Out To: <comma-separated list of outgoing dependency files>
        
        Snippet:
        <node.codeSnippet>
        ```

### Phase 3: Embedding and Registration
1.  **Vectorize:** Send the synthesized Meta-Text string to the embedding API to generate the dense vector representation.
2.  **Store:** Save the `<node.id>` and its corresponding vector into the `VectorService`.

### Phase 4: MCP Tool Exposure
1.  **Create `semantic_search_nodes` Tool:** In `mcp-server/src/index.ts`, register a new MCP tool named `semantic_search_nodes`.
    *   **Arguments:** `{ query: string, top_k?: number }`
    *   **Description:** "Translates a natural language task intent into the best underlying structural root nodes for further graph traversal."
2.  **Execution Logic:**
    *   Embed the user's `query`.
    *   Query the `VectorService` for the top *k* nearest vectors.
    *   Return the corresponding `node_id` strings, along with their names and file paths, back to the MCP Client.

This implementation successfully bridges the intent-to-structure gap, allowing the agent to use `semantic_search_nodes("fix 2FA bypass")`, receive `src/auth/2fa.ts:validateOTP` as the top result, and immediately proceed to advanced structural tools like `get_call_chain_to()` or `analyze_refactor_impact()`.
