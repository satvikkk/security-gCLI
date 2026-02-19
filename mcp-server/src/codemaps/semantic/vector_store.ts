import { VectorDocument, SemanticQueryResult } from "./types.js";
import fs from "fs/promises";
import path from "path";

/**
 * A lightweight, in-memory vector store that persists to a JSON file.
 * Uses dot product cosine similarity for querying.
 */
export class VectorStore {
  private documents: VectorDocument[] = [];
  private filePath: string;

  constructor(storagePath?: string) {
    // Default to a hidden file in the user's home dir or .gemini_security/vectors.json
    // For now, let's keep it relative to the mcp-server root or a passed path
    this.filePath = storagePath || path.resolve(process.cwd(), ".gemini_security", "vectors.json");
  }

  get size(): number {
    return this.documents.length;
  }

  async add(doc: VectorDocument): Promise<void> {
    // Upsert logic: Remove existing doc with same ID if present
    this.documents = this.documents.filter(d => d.id !== doc.id);
    this.documents.push(doc);
  }

  async save(): Promise<void> {
    const dir = path.dirname(this.filePath);
    try {
      await fs.mkdir(dir, { recursive: true });
      await fs.writeFile(this.filePath, JSON.stringify(this.documents, null, 2), "utf-8");
    } catch (error) {
      console.error(`[VectorStore] Failed to save vectors to ${this.filePath}:`, error);
    }
  }

  async load(): Promise<void> {
    try {
      const data = await fs.readFile(this.filePath, "utf-8");
      this.documents = JSON.parse(data);
    } catch (error: any) {
      if (error.code === 'ENOENT') {
        // File doesn't exist yet, start fresh
        this.documents = [];
        return;
      }
      console.error(`[VectorStore] Failed to load vectors from ${this.filePath}:`, error);
      throw error;
    }
  }

  /**
   * Finds the top k most similar documents to the query vector.
   */
  async query(queryVector: number[], k: number = 5): Promise<SemanticQueryResult[]> {
    if (this.documents.length === 0) return [];

    // Check dimension mismatch on first doc
    if (this.documents[0].vector.length !== queryVector.length) {
      console.warn(`[VectorStore] Dimension mismatch: Doc=${this.documents[0].vector.length}, Query=${queryVector.length}`);
      // Proceeding anyway but results might be garbage or method might fail if logic relies on exact length matching
    }

    const scored: SemanticQueryResult[] = this.documents.map(doc => ({
      document: doc,
      score: this.cosineSimilarity(queryVector, doc.vector)
    }));

    // Sort descending by score
    scored.sort((a, b) => b.score - a.score);

    return scored.slice(0, k);
  }

  private cosineSimilarity(vecA: number[], vecB: number[]): number {
    let dotProduct = 0;
    let normA = 0;
    let normB = 0;
    for (let i = 0; i < vecA.length; i++) {
      dotProduct += vecA[i] * vecB[i];
      normA += vecA[i] * vecA[i];
      normB += vecB[i] * vecB[i];
    }
    if (normA === 0 || normB === 0) return 0;
    return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
  }
}
