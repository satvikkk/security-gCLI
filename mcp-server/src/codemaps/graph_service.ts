/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  GraphNode,
  GraphEdge,
  SymbolSearchResult,
  SymbolDetails,
} from './models.js';
import { promises as fs } from 'fs';
import path from 'path';

export class GraphService {
  public graph: {
    nodes: Map<string, GraphNode>;
    edges: Map<string, GraphEdge[]>; // Adjacency list for outgoing edges
    inEdges: Map<string, GraphEdge[]>; // For incoming edges
  };
  private _byName: Map<string, Set<string>>;
  private _byFileAndName: Map<string, string>;
  public _pendingCalls: [string, string, string][];
  private _fileManifest: Set<string> = new Set();
  private _pathAliases: { alias: string; path: string }[] = [];
  private _projectRoot = '';
  private _goModuleName: string | null = null;

  constructor() {
    this.graph = {
      nodes: new Map(),
      edges: new Map(),
      inEdges: new Map(),
    };
    this._byName = new Map();
    this._byFileAndName = new Map();
    this._pendingCalls = [];
  }

  public async initialize(projectRoot: string) {
    this._projectRoot = projectRoot;
    await this._buildFileManifest(projectRoot);
    await this._loadTsConfigAliases(projectRoot);
    await this._loadGoModuleInfo(projectRoot);
  }

  private async _buildFileManifest(dir: string) {
    const dirents = await fs.readdir(dir, { withFileTypes: true });
    for (const dirent of dirents) {
      const res = path.resolve(dir, dirent.name);
      if (dirent.name === 'node_modules' || dirent.name === '.git') {
        continue;
      }
      if (dirent.isDirectory()) {
        await this._buildFileManifest(res);
      } else {
        if (
          res.endsWith('.ts') ||
          res.endsWith('.tsx') ||
          res.endsWith('.js') ||
          res.endsWith('.py') ||
          res.endsWith('.go')
        ) {
          this._fileManifest.add(res);
        }
      }
    }
  }

  private async _loadTsConfigAliases(projectRoot: string) {
    try {
      const tsConfigPath = path.join(projectRoot, 'tsconfig.json');
      const tsConfigContent = await fs.readFile(tsConfigPath, 'utf8');
      let tsConfig;
      try {
        const jsonc = tsConfigContent.replace(
          /\/\*[\s\S]*?\*\/|([^\\:]|^)\/\/.*$/gm,
          '$1'
        );
        tsConfig = JSON.parse(jsonc);
      } catch (e) {
        console.error(
          `Error parsing tsconfig.json at ${tsConfigPath}. It might be invalid JSONC.`
        );
        return;
      }
      const paths = tsConfig.compilerOptions?.paths;
      if (paths) {
        const baseUrl = tsConfig.compilerOptions?.baseUrl || '.';
        for (const alias in paths) {
          const aliasPath = paths[alias][0];
          const cleanAlias = alias.endsWith('/*') ? alias.slice(0, -2) : alias;
          const cleanPath = aliasPath.endsWith('/*')
            ? aliasPath.slice(0, -2)
            : aliasPath;
          this._pathAliases.push({
            alias: cleanAlias,
            path: path.resolve(projectRoot, baseUrl, cleanPath),
          });
        }
        this._pathAliases.sort((a, b) => b.alias.length - a.alias.length);
      }
    } catch (error) {
      // It's okay if tsconfig.json doesn't exist.
    }
  }

  private async _loadGoModuleInfo(projectRoot: string) {
    try {
      const goModPath = path.join(projectRoot, 'go.mod');
      const goModContent = await fs.readFile(goModPath, 'utf8');
      const match = goModContent.match(/^module\s+([^\s]+)/m);
      if (match) {
        this._goModuleName = match[1];
      }
    } catch (error) {
      // It's okay if go.mod doesn't exist.
    }
  }

  public resolveModuleId(
    moduleName: string,
    containingFilePath: string,
    language: string
  ): string {
    let resolvedPath: string | null = null;
    let fileId: string | null = null;

    switch (language) {
      case 'typescript':
      case 'javascript':
        for (const { alias, path: aliasPath } of this._pathAliases) {
          if (moduleName.startsWith(alias)) {
            resolvedPath = path.join(
              aliasPath,
              moduleName.substring(alias.length)
            );
            fileId = this._findFileInManifest(resolvedPath, language);
            if (fileId) return fileId;
          }
        }
        if (moduleName.startsWith('./') || moduleName.startsWith('../')) {
          resolvedPath = path.resolve(
            path.dirname(containingFilePath),
            moduleName
          );
          fileId = this._findFileInManifest(resolvedPath, language);
          if (fileId) return fileId;
        }
        break;

      case 'go':
        if (this._goModuleName && moduleName.startsWith(this._goModuleName)) {
          const subPath = moduleName.substring(this._goModuleName.length);
          resolvedPath = path.join(this._projectRoot, subPath);
          fileId = this._findFileInManifest(resolvedPath, language);
          if (fileId) return fileId;
        }
        break;

      case 'python':
        const pyPath = moduleName.replace(/\./g, '/');
        // Check relative to project root
        resolvedPath = path.join(this._projectRoot, pyPath);
        fileId = this._findFileInManifest(resolvedPath, language);
        if (fileId) return fileId;

        // Check relative to current file (for imports like `from . import ...`)
        if (moduleName.startsWith('.')) {
            let tempResolvedPath = path.resolve(path.dirname(containingFilePath), pyPath.substring(1));
            fileId = this._findFileInManifest(tempResolvedPath, language);
            if (fileId) return fileId;
        }
        break;
    }

    return this.ensureModuleNode(moduleName);
  }

  private _findFileInManifest(
    resolvedPath: string,
    language: string
  ): string | null {
    const extensions = this._getExtensionsForLanguage(language);
    const indexNames = this._getIndexNamesForLanguage(language);

    if (this._fileManifest.has(resolvedPath)) {
      return resolvedPath;
    }

    if (
      (language === 'typescript' || language === 'javascript') &&
      resolvedPath.endsWith('.js')
    ) {
      const tsPath = resolvedPath.slice(0, -3) + '.ts';
      if (this._fileManifest.has(tsPath)) {
        return tsPath;
      }
      const tsxPath = resolvedPath.slice(0, -3) + '.tsx';
      if (this._fileManifest.has(tsxPath)) {
        return tsxPath;
      }
    }

    for (const ext of extensions) {
      const fullPath = `${resolvedPath}${ext}`;
      if (this._fileManifest.has(fullPath)) {
        return fullPath;
      }
    }

    for (const indexName of indexNames) {
      const indexPath = path.join(resolvedPath, indexName);
      if (this._fileManifest.has(indexPath)) {
        return indexPath;
      }
    }

    return null;
  }

  private _getExtensionsForLanguage(language: string): string[] {
    switch (language) {
      case 'typescript':
        return ['.ts', '.tsx'];
      case 'javascript':
        return ['.js'];
      case 'python':
        return ['.py'];
      case 'go':
        return ['.go'];
      default:
        return [];
    }
  }

  private _getIndexNamesForLanguage(language: string): string[] {
    switch (language) {
      case 'typescript':
        return ['index.ts', 'index.tsx'];
      case 'javascript':
        return ['index.js'];
      case 'python':
        return ['__init__.py'];
      default:
        return [];
    }
  }

  private _indexNode(nodeId: string, nodeData: GraphNode) {
    const name = nodeData.name;
    if (name) {
      if (!this._byName.has(name)) {
        this._byName.set(name, new Set());
      }
      this._byName.get(name)!.add(nodeId);

      const filePath = nodeId.split(':', 1)[0];
      this._byFileAndName.set(`${filePath}:${name}`, nodeId);
    }
  }

  public addNode(node: GraphNode) {
    this.graph.nodes.set(node.id, node);
    this._indexNode(node.id, node);
  }

  public addEdge(edge: GraphEdge) {
    if (!this.graph.edges.has(edge.source)) {
      this.graph.edges.set(edge.source, []);
    }
    this.graph.edges.get(edge.source)!.push(edge);

    if (!this.graph.inEdges.has(edge.target)) {
      this.graph.inEdges.set(edge.target, []);
    }
    this.graph.inEdges.get(edge.target)!.push(edge);
  }

  public findEnclosingEntity(
    filePath: string,
    lineNumber: number
  ): GraphNode | null {
    const enclosingNodes: GraphNode[] = [];
    for (const node of this.graph.nodes.values()) {
      if (node.id.startsWith(filePath) && node.type !== 'file') {
        if (node.startLine <= lineNumber && node.endLine >= lineNumber) {
          enclosingNodes.push(node);
        }
      }
    }

    if (enclosingNodes.length === 0) {
      return null;
    }

    // Find the most specific entity (smallest line range)
    return enclosingNodes.reduce((mostSpecific, current) => {
      const specificRange = mostSpecific.endLine - mostSpecific.startLine;
      const currentRange = current.endLine - current.startLine;
      return currentRange < specificRange ? current : mostSpecific;
    });
  }

  public querySymbol(name: string, filePath?: string): GraphNode | null {
    if (filePath) {
      const key = `${filePath}:${name}`;
      if (this._byFileAndName.has(key)) {
        const nodeId = this._byFileAndName.get(key);
        if (nodeId) {
          return this.graph.nodes.get(nodeId) || null;
        }
      }
    }
    const ids = this._byName.get(name);
    if (ids && ids.size === 1) {
      const nodeId = ids.values().next().value;
      if (nodeId) {
        return this.graph.nodes.get(nodeId) || null;
      }
    }
    // Ambiguous or not found
    return null;
  }

  public searchSymbol(
    query: string,
    typeFilter?: string
  ): SymbolSearchResult[] {
    const results: SymbolSearchResult[] = [];
    const normalizedQuery = query.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();

    for (const [name, nodeIds] of this._byName.entries()) {
      const normalizedName = name.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
      if (normalizedName.includes(normalizedQuery)) {
        for (const nodeId of nodeIds) {
          const node = this.graph.nodes.get(nodeId);
          if (node) {
            if (typeFilter && node.type !== typeFilter) {
              continue;
            }
            results.push({
              name: node.name,
              type: node.type,
              filePath: node.id.split(':', 1)[0],
              location: {
                startLine: node.startLine,
                endLine: node.endLine,
              },
              score: query.length / name.length, // Simple scoring
            });
          }
        }
      }
    }
    return results.sort((a, b) => b.score - a.score);
  }

  public getSymbolDetails(
    symbol: string,
    filePath?: string
  ): SymbolDetails | null {
    const node = this.querySymbol(symbol, filePath);
    if (!node) {
      return null;
    }

    const relationships: SymbolDetails['relationships'] = {
      parentClasses: [],
      callees: [],
      callers: [],
      children: [],
    };

    const outgoingEdges = this.graph.edges.get(node.id) || [];
    for (const edge of outgoingEdges) {
      const targetNode = this.graph.nodes.get(edge.target);
      if (targetNode) {
        if (edge.type === 'inherits') {
          relationships.parentClasses.push(targetNode);
        } else if (edge.type === 'calls') {
          relationships.callees.push(targetNode);
        } else if (edge.type === 'contains') {
          relationships.children.push(targetNode);
        }
      }
    }

    const incomingEdges = this.graph.inEdges.get(node.id) || [];
    for (const edge of incomingEdges) {
      if (edge.type === 'calls') {
        const sourceNode = this.graph.nodes.get(edge.source);
        if (sourceNode) {
          relationships.callers.push(sourceNode);
        }
      }
    }

    return {
      ...node,
      relationships,
    };
  }

  public findReferences(symbol: string, filePath?: string): GraphNode[] {
    const node = this.querySymbol(symbol, filePath);
    if (!node) {
      return [];
    }

    const callers: GraphNode[] = [];
    const incomingEdges = this.graph.inEdges.get(node.id) || [];
    for (const edge of incomingEdges) {
      if (edge.type === 'calls') {
        const sourceNode = this.graph.nodes.get(edge.source);
        if (sourceNode) {
          callers.push(sourceNode);
        }
      }
    }
    return callers;
  }

  public getFileStructure(filePath: string): GraphNode | null {
    const fileNode = this.graph.nodes.get(filePath);
    if (!fileNode) {
      return null;
    }

    const buildTree = (nodeId: string): any => {
      const node = this.graph.nodes.get(nodeId);
      if (!node) return null;

      const children: any[] = [];
      const outgoingEdges = this.graph.edges.get(nodeId) || [];
      for (const edge of outgoingEdges) {
        if (edge.type === 'contains') {
          const childTree = buildTree(edge.target);
          if (childTree) {
            children.push(childTree);
          }
        }
      }

      const result = { ...node };
      if (children.length > 0) {
        (result as any).children = children;
      }
      return result;
    };

    return buildTree(filePath);
  }

  public getOutgoingDependencies(filePath: string): GraphNode[] {
    const dependencies: GraphNode[] = [];
    const outgoingEdges = this.graph.edges.get(filePath) || [];
    for (const edge of outgoingEdges) {
      if (edge.type === 'imports') {
        const targetNode = this.graph.nodes.get(edge.target);
        if (targetNode) {
          dependencies.push(targetNode);
        }
      }
    }
    return dependencies;
  }

  public clearFile(filePath: string) {
    const nodesToRemove: string[] = [];
    for (const nodeId of this.graph.nodes.keys()) {
      if (nodeId.startsWith(filePath)) {
        nodesToRemove.push(nodeId);
      }
    }

    for (const nodeId of nodesToRemove) {
      // Clean up outgoing edges
      const outgoing = this.graph.edges.get(nodeId) || [];
      for (const edge of outgoing) {
        const targetInEdges = this.graph.inEdges.get(edge.target);
        if (targetInEdges) {
          this.graph.inEdges.set(
            edge.target,
            targetInEdges.filter((e) => e.source !== nodeId)
          );
        }
      }
      this.graph.edges.delete(nodeId);

      // Clean up incoming edges
      const incoming = this.graph.inEdges.get(nodeId) || [];
      for (const edge of incoming) {
        const sourceOutEdges = this.graph.edges.get(edge.source);
        if (sourceOutEdges) {
          this.graph.edges.set(
            edge.source,
            sourceOutEdges.filter((e) => e.target !== nodeId)
          );
        }
      }
      this.graph.inEdges.delete(nodeId);

      // Clean up node and its indexes
      const node = this.graph.nodes.get(nodeId);
      if (node) {
        if (this._byName.has(node.name)) {
          this._byName.get(node.name)!.delete(nodeId);
          if (this._byName.get(node.name)!.size === 0) {
            this._byName.delete(node.name);
          }
        }
        this._byFileAndName.delete(`${filePath}:${node.name}`);
        this.graph.nodes.delete(nodeId);
      }
    }
  }

  public ensureModuleNode(moduleName: string): string {
    const nodeId = `module:${moduleName}`;
    if (!this.graph.nodes.has(nodeId)) {
      const node: GraphNode = {
        id: nodeId,
        type: 'module',
        name: moduleName,
        startLine: 0,
        endLine: 0,
        documentation: '',
        codeSnippet: '',
      };
      this.addNode(node);
    }
    return nodeId;
  }

  public addPendingCall(
    filePath: string,
    sourceId: string,
    calleeName: string
  ) {
    this._pendingCalls.push([filePath, sourceId, calleeName]);
  }

  public async saveGraph(outputDir: string) {
    const filePath = path.join(outputDir, 'codemap.json');
    const graphJson = {
      nodes: Array.from(this.graph.nodes.values()),
      edges: Array.from(this.graph.edges.values()).flat(),
    };
    await fs.mkdir(outputDir, { recursive: true });
    await fs.writeFile(filePath, JSON.stringify(graphJson, null, 2));
  }
  public async loadGraph(outputDir: string): Promise<boolean> {
    const filePath = path.join(outputDir, 'codemap.json');
    try {
      const data = await fs.readFile(filePath, 'utf8');
      const graphJson = JSON.parse(data);

      this.graph.nodes.clear();
      this.graph.edges.clear();
      this.graph.inEdges.clear();
      this._byName.clear();
      this._byFileAndName.clear();
      this._pendingCalls = [];

      for (const node of graphJson.nodes) {
        this.addNode(node);
      }

      for (const edge of graphJson.edges) {
        this.addEdge(edge);
      }
      return true;
    } catch (error) {
      return false;
    }
  }
}
