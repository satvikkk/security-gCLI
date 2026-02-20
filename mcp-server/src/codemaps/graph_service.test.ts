/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { GraphService } from './graph_service';
import { GraphNode } from './models';

describe('GraphService', () => {
  let graphService: GraphService;

  beforeEach(() => {
    graphService = new GraphService();
  });

  it('should add a node to the graph', () => {
    const node: GraphNode = {
      id: 'file.py:my_function',
      type: 'function',
      name: 'my_function',
      startLine: 1,
      endLine: 10,
      documentation: '',
      codeSnippet: '',
    };
    graphService.addNode(node);
    expect(graphService.graph.nodes.get('file.py:my_function')).toEqual(node);
  });

  it('should add an edge to the graph', () => {
    const edge = {
      source: 'file.py:my_function',
      target: 'file.py:another_function',
      type: 'calls',
    };
    graphService.addEdge(edge);
    expect(graphService.graph.edges.get('file.py:my_function')).toEqual([
      edge,
    ]);
    expect(
      graphService.graph.inEdges.get('file.py:another_function')
    ).toEqual([edge]);
  });

  it('should find the enclosing entity', () => {
    const fileNode: GraphNode = {
      id: 'file.py',
      type: 'file',
      name: 'file.py',
      startLine: 0,
      endLine: 0,
      documentation: '',
      codeSnippet: '',
    };
    const functionNode: GraphNode = {
      id: 'file.py:my_function',
      type: 'function',
      name: 'my_function',
      startLine: 1,
      endLine: 10,
      documentation: '',
      codeSnippet: '',
    };
    const innerFunctionNode: GraphNode = {
      id: 'file.py:my_function:inner',
      type: 'function',
      name: 'inner',
      startLine: 2,
      endLine: 5,
      documentation: '',
      codeSnippet: '',
    };
    graphService.addNode(fileNode);
    graphService.addNode(functionNode);
    graphService.addNode(innerFunctionNode);

    const enclosingEntity = graphService.findEnclosingEntity('file.py', 3);
    expect(enclosingEntity).toEqual(innerFunctionNode);
  });

  it('should query a symbol', () => {
    const node: GraphNode = {
      id: 'file.py:my_function',
      type: 'function',
      name: 'my_function',
      startLine: 1,
      endLine: 10,
      documentation: '',
      codeSnippet: '',
    };
    graphService.addNode(node);

    const foundNode = graphService.querySymbol('my_function', 'file.py');
    expect(foundNode).toEqual(node);
  });

  it('should search for a symbol', () => {
    const node: GraphNode = {
      id: 'file.py:my_function',
      type: 'function',
      name: 'my_function',
      startLine: 1,
      endLine: 10,
      documentation: '',
      codeSnippet: '',
    };
    graphService.addNode(node);
    const results = graphService.searchSymbol('my_func');
    expect(results).toHaveLength(1);
    expect(results[0].name).toEqual('my_function');
  });

  it('should get symbol details', () => {
    const node: GraphNode = {
      id: 'file.py:my_function',
      type: 'function',
      name: 'my_function',
      startLine: 1,
      endLine: 10,
      documentation: '',
      codeSnippet: '',
    };
    graphService.addNode(node);
    const details = graphService.getSymbolDetails('my_function', 'file.py');
    expect(details?.name).toEqual('my_function');
  });

  it('should find references to a symbol', () => {
    const functionNode: GraphNode = {
      id: 'file.py:my_function',
      type: 'function',
      name: 'my_function',
      startLine: 1,
      endLine: 10,
      documentation: '',
      codeSnippet: '',
    };
    const callerNode: GraphNode = {
      id: 'file.py:caller',
      type: 'function',
      name: 'caller',
      startLine: 11,
      endLine: 20,
      documentation: '',
      codeSnippet: '',
    };
    graphService.addNode(functionNode);
    graphService.addNode(callerNode);
    graphService.addEdge({
      source: 'file.py:caller',
      target: 'file.py:my_function',
      type: 'calls',
    });
    const references = graphService.findReferences('my_function', 'file.py');
    expect(references).toHaveLength(1);
    expect(references[0].name).toEqual('caller');
  });

  it('should get the file structure', () => {
    const fileNode: GraphNode = {
      id: 'file.py',
      type: 'file',
      name: 'file.py',
      startLine: 0,
      endLine: 0,
      documentation: '',
      codeSnippet: '',
    };
    const functionNode: GraphNode = {
      id: 'file.py:my_function',
      type: 'function',
      name: 'my_function',
      startLine: 1,
      endLine: 10,
      documentation: '',
      codeSnippet: '',
    };
    graphService.addNode(fileNode);
    graphService.addNode(functionNode);
    graphService.addEdge({
      source: 'file.py',
      target: 'file.py:my_function',
      type: 'contains',
    });
    const structure = graphService.getFileStructure('file.py') as any;
    expect(structure.name).toEqual('file.py');
    expect(structure.children).toHaveLength(1);
    expect(structure.children[0].name).toEqual('my_function');
  });

  it('should get outgoing dependencies', () => {
    const fileNode: GraphNode = {
      id: 'file.py',
      type: 'file',
      name: 'file.py',
      startLine: 0,
      endLine: 0,
      documentation: '',
      codeSnippet: '',
    };
    const moduleNode: GraphNode = {
      id: 'module:os',
      type: 'module',
      name: 'os',
      startLine: 0,
      endLine: 0,
      documentation: '',
      codeSnippet: '',
    };
    graphService.addNode(fileNode);
    graphService.addNode(moduleNode);
    graphService.addEdge({
      source: 'file.py',
      target: 'module:os',
      type: 'imports',
    });
    const dependencies = graphService.getOutgoingDependencies('file.py');
    expect(dependencies).toHaveLength(1);
    expect(dependencies[0].name).toEqual('os');
  });

  it('should clear a file from the graph', () => {
    const fileNode: GraphNode = {
      id: 'file.py',
      type: 'file',
      name: 'file.py',
      startLine: 0,
      endLine: 0,
      documentation: '',
      codeSnippet: '',
    };
    const functionNode: GraphNode = {
      id: 'file.py:my_function',
      type: 'function',
      name: 'my_function',
      startLine: 1,
      endLine: 10,
      documentation: '',
      codeSnippet: '',
    };
    graphService.addNode(fileNode);
    graphService.addNode(functionNode);
    graphService.clearFile('file.py');
    expect(graphService.graph.nodes.has('file.py')).toBe(false);
    expect(graphService.graph.nodes.has('file.py:my_function')).toBe(false);
  });

  it('should find references to a class that is instantiated', () => {
    const serviceNode: GraphNode = {
      id: 'src/my_service.ts:MyService',
      type: 'class',
      name: 'MyService',
      startLine: 2,
      endLine: 5,
      documentation: '',
      codeSnippet: 'export class MyService {\n  constructor() {}\n}\n',
    };
    const mainFileNode: GraphNode = {
      id: 'src/main.ts',
      type: 'file',
      name: 'main.ts',
      startLine: 0,
      endLine: 0,
      documentation: '',
      codeSnippet: '',
    };
    graphService.addNode(serviceNode);
    graphService.addNode(mainFileNode);
    graphService.addEdge({
      source: 'src/main.ts',
      target: 'src/my_service.ts:MyService',
      type: 'instantiates',
    });
    const references = graphService.findReferences('MyService', 'src/my_service.ts');
    expect(references).toHaveLength(1);
    expect(references[0].id).toEqual('src/main.ts');
  });
});
