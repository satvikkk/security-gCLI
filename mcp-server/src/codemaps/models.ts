/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

export interface GraphNode {
  id: string;
  type: string;
  name: string;
  startLine: number;
  endLine: number;
  documentation: string;
  codeSnippet: string;
  llmSummary?: string;
}

export interface GraphEdge {
  source: string;
  target: string;
  type: string;
  weight?: number;
  locations?: { line: number; snippet?: string }[];
}

export interface SymbolSearchResult {
  name: string;
  type: string;
  filePath: string;
  location: {
    startLine: number;
    endLine: number;
  };
  score: number;
}

export interface RelatedSymbol extends GraphNode {
  weight?: number;
  locations?: { line: number; snippet?: string }[];
}

export interface SymbolDetails extends GraphNode {
  relationships: {
    parentClasses: RelatedSymbol[];
    callees: RelatedSymbol[];
    callers: RelatedSymbol[];
    children: RelatedSymbol[];
  };
}
