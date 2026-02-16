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

## Implementation Next Steps
To build the "Intent-to-Structure" bridge, the immediate next step for the `mcp-server` is implementing **Strategy 1**. 

The backend should be updated to maintain a local vector store (e.g., using a lightweight local SQLite-VSS or simple cosine similarity array). When calculating the graph, it must generate Neighborhood-Augmented text blurbs for every node and vectorize them, exposing a new MCP Tool: `semantic_search_nodes(query_string)` that returns the optimal `node_id` starting points.
