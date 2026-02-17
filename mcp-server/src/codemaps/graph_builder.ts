/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import Parser from 'tree-sitter';
import { GraphService } from './graph_service.js';
import { GraphNode } from './models.js';
import { PythonParser } from './parsers/python_parser.js';
import { JavaScriptParser } from './parsers/javascript_parser.js';
import { GoParser } from './parsers/go_parser.js';
import { TypeScriptParser } from './parsers/typescript_parser.js';
import { LanguageParser } from './parsers/base_parser.js';
import { promises as fs } from 'fs';
import path from 'path';
import Python from 'tree-sitter-python';
import JavaScript from 'tree-sitter-javascript';
import Go from 'tree-sitter-go';
import TypeScript from 'tree-sitter-typescript';

export class GraphBuilder {
  private parser!: Parser;
  private languageParsers: { [key: string]: LanguageParser };
  private languages: { [key: string]: object };
  private isInitialized = false;
  private projectRoot: string | null = null;
    constructor(private graphService: GraphService) {
      this.languageParsers = {
        python: new PythonParser(graphService),
        javascript: new JavaScriptParser(graphService),
        go: new GoParser(graphService),
        typescript: new TypeScriptParser(graphService),
      };
      this.languages = {
          python: Python,
          javascript: JavaScript,
          go: Go,
          typescript: TypeScript.typescript,
      };
    }

    public async buildGraph(filePath: string) {
      if (!this.isInitialized) {
        await this._findAndSetProjectRoot(filePath);
        await this.graphService.initialize(this.projectRoot!);
        this.isInitialized = true;
      }
      const language = this._getLanguageFromFileExtension(filePath);
      const languageMapping = this.languages[language];
    if (!languageMapping) {
        throw new Error(`Unsupported language: ${language}`);
    }

    this.parser = new Parser();
    this.parser.setLanguage(languageMapping);

    const fileContent = await fs.readFile(filePath, 'utf8');
    const tree = this.parser.parse(fileContent);
    const fileNode: GraphNode = {
        id: filePath,
        type: 'file',
        name: filePath,
        startLine: 0,
        endLine: 0,
        documentation: '',
        codeSnippet: '',
    };
    this.graphService.addNode(fileNode);
    const languageParser = this.languageParsers[language];
    this._traverseTree(tree.rootNode, languageParser, filePath, filePath);
    return this.graphService.graph;
  }


  private async _findAndSetProjectRoot(startPath: string): Promise<void> {
    let currentPath = path.dirname(startPath);
    const rootMarkers = [
      'package.json',
      '.git',
      'go.mod',
      'pyproject.toml',
      'requirements.txt',
    ];
    while (currentPath !== path.dirname(currentPath)) {
      for (const marker of rootMarkers) {
        try {
          await fs.access(path.join(currentPath, marker));
          this.projectRoot = currentPath;
          return;
        } catch (e) {
          // Ignore and continue
        }
      }
      currentPath = path.dirname(currentPath);
    }
    throw new Error(`Could not determine project root from ${startPath}.`);
  }

  private _traverseTree(node: Parser.SyntaxNode, languageParser: LanguageParser, filePath: string, scope: string) {
    const newScope = languageParser.parse(node, filePath, scope);
    for (const child of node.children) {
      this._traverseTree(child, languageParser, filePath, newScope);
    }
  }

  private _getLanguageFromFileExtension(filePath: string): string {
    if (filePath.endsWith('.py')) {
      return 'python';
    } else if (filePath.endsWith('.js')) {
      return 'javascript';
    } else if (filePath.endsWith('.ts') || filePath.endsWith('.tsx')) {
      return 'typescript';
    } else if (filePath.endsWith('.go')) {
      return 'go';
    } else {
      throw new Error(`Unsupported file extension: ${filePath}`);
    }
  }
}
