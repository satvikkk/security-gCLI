# CodeMaps: The "Agent's Compiler" Feature Roadmap

This document outlines the vision and technical specifications for expanding the `codemaps` backend from a passive structural graph generator into an active, queryable **Compiler for LLM Agents**. 

By exposing graph theory algorithms and traversal techniques as native MCP tools, we shift the agent's paradigm away from token-heavy full-text searches toward instantaneous, perfect structural queries.

These are the proposed features to track in the `mcp-server` roadmap:

---

## 1. Contextual Boundary Slicing (The "Need to Know" Tool)
**Goal:** Prevent agents from being overloaded with the entire repository when investigating a single feature or file.

*   **Graph Technique:** Ego-Network / Subgraph Extraction
*   **Proposed MCP Tool:** `get_component_context(node_id, max_depth=1)`
*   **Behavior:** The backend extracts a self-contained subgraph showing the target node, everything it directly calls/imports, and everything that directly calls/imports *it*, up to `max_depth` hops.
*   **Agent Utility:** The LLM gets a perfectly scoped playground. When tasked with modifying "billing.ts", it instantly sees exactly what standard utilities it relies on, and which external modules will be affected if it breaks.

## 2. Feature Tracing (The "How does this work?" Tool)
**Goal:** Allow the LLM to understand logic flow across multiple disconnected files without having to hop backward file-by-file in the context window.

*   **Graph Technique:** Forward-Directed Walk / Tree Traversal
*   **Proposed MCP Tool:** `trace_execution_flow(entry_node_id)`
*   **Behavior:** The graph backend recursively walks `calls` edges continuously downstream originating from `entry_node_id`. It compiles the resulting tree into an ordered execution trace.
*   **Agent Utility:** The agent receives a concise JSON summary of the request lifecycle (e.g., `AuthRouter -> validate() -> Controller -> executeQuery() -> DB`). It instantly understands the flow without reading hundreds of lines of routing boilerplate.

## 3. Impact Analysis / Refactor Planning (The "Will I break something?" Tool)
**Goal:** Empower the agent to safely refactor core utilities or rename shared interfaces by explicitly knowing the blast radius.

*   **Graph Technique:** Reverse Reachability / Transitive Closure
*   **Proposed MCP Tool:** `analyze_refactor_impact(node_id)`
*   **Behavior:** It traverses all *incoming* edges (`calls`, `imports`, `inherits`), recursively climbing up the tree to identify every module, function, and class that eventually triggers the target node.
*   **Agent Utility:** The agent can unequivocally state, "I cannot safely delete or change the signature of `sanitizeString()` because it is transitively relied upon by 14 distinct API endpoints." 

## 4. Resolving Symbols (The "Where is this defined?" Tool)
**Goal:** Eliminate the need for agents to run inaccurate `grep` regex searches to find where a variable, class, or function is actually defined.

*   **Graph Technique:** Scoped Traversal / Node Attribute lookup
*   **Proposed MCP Tool:** `resolve_symbol(symbol_name, source_file_path)`
*   **Behavior:** Taking a string and the context file where the LLM saw the string, the graph traces the `imports` rules explicitly mapped to that file, or the internal AST scope of that file, to locate the True `node_id` defining that symbol.
*   **Agent Utility:** The agent asks "Where does `processPayment` live from here?" and instantly gets the absolute file path and line number coordinates (`/src/payments/stripe.ts:42`), allowing it to jump precisely to that location via `read_file`.

## 5. Architectural Querying & Pattern Matching
**Goal:** Allow the LLM to inspect the structural integrity and high-level design of the entire repository instantaneously.

*   **Graph Technique:** Subgraph Isomorphism / Constraint Filtering
*   **Proposed MCP Tools:**
    *   `query_architecture(pattern)`: Returns all nodes matching a structural fingerprint (e.g. "Find all classes inheriting from generic Controller").
    *   `find_structural_drift(ruleset)`: Validates architecture logic against rules (e.g. "Flag any logic paths where the Presentation layer calls the Database layer directly without passing through a Service layer").
*   **Agent Utility:** Massively accelerates zero-day vulnerability hunting and codebase orientation. The LLM can interrogate the overall design instead of blindly hunting for text.

## 6. Dead Code / Orphan Component Detection (The "Cleanup" Tool)
**Goal:** Facilitate safe repository cleanup assignments.

*   **Graph Technique:** Disconnected Component Analysis / Outlier Detection (In-degree = 0)
*   **Proposed MCP Tool:** `find_isolated_components(directory_path)`
*   **Behavior:** The backend algorithm identifies structural nodes inside the given directory that have absolutely 0 incoming structural edges (excluding expected uncalled roots like `index.ts` or exported hooks).
*   **Agent Utility:** The agent can instantly list internally defined helper functions or deprecated legacy classes that are no longer referenced anywhere and propose them for safe deletion.
