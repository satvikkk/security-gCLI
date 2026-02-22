#!/bin/bash
# run_all_semantic_strategies.sh

echo "================================================="
echo "🧠 Running All Advanced Semantic Search Strategies"
echo "================================================="

# Run the first one with --force to ensure a clean slate and build the index
echo -e "\n\n=== 1. Flat Semantic Search (Building Index) ==="
npx tsx src/test_semantic_standalone.ts --force --mock-llm

echo -e "\n\n=== 2. GraphRAG (Component Expansion) ==="
npx tsx src/test_semantic_standalone.ts --strategy=graph_rag --mock-llm

echo -e "\n\n=== 3. Hierarchical (Top-Down) Search ==="
npx tsx src/test_semantic_standalone.ts --strategy=hierarchical --mock-llm

echo -e "\n\n=== 4. Structural Agentic Routing ==="
npx tsx src/test_semantic_standalone.ts --strategy=agentic_router --mock-llm

echo -e "\n\n================================================="
echo "✅ All strategies completed successfully!"
