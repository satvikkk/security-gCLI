import * as ts from 'typescript';
import * as fs from 'fs';

export function getFunctionContext(filePath: string, lineNumber: number): { startLine: number; endLine: number } | null {
  try {
    const fileContent = fs.readFileSync(filePath, 'utf8');
    const sourceFile = ts.createSourceFile(filePath, fileContent, ts.ScriptTarget.Latest, true);

    let containingFunction: { startLine: number; endLine: number } | null = null;

    function visit(node: ts.Node) {
      if (
        ts.isFunctionDeclaration(node) ||
        ts.isMethodDeclaration(node) ||
        ts.isArrowFunction(node) ||
        ts.isFunctionExpression(node)
      ) {
        const start = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
        const end = sourceFile.getLineAndCharacterOfPosition(node.getEnd());

        const startLine = start.line + 1;
        const endLine = end.line + 1;

        if (lineNumber >= startLine && lineNumber <= endLine) {
          if (
            !containingFunction ||
            (startLine >= containingFunction.startLine && endLine <= containingFunction.endLine)
          ) {
            containingFunction = { startLine, endLine };
          }
        }
      }
      ts.forEachChild(node, visit);
    }

    visit(sourceFile);
    return containingFunction;
  } catch (error) {
    console.error(`Error processing file ${filePath}:`, error);
    return null;
  }
}
