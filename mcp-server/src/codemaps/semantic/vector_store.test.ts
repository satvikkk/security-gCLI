import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { VectorStore } from './vector_store.js';
import { VectorDocument } from './types.js';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

describe('VectorStore', () => {
    let tmpDir: string;
    let storePath: string;
    let store: VectorStore;

    beforeEach(async () => {
        tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vector-tests-'));
        storePath = path.join(tmpDir, 'vectors.json');
        store = new VectorStore(storePath);
    });

    afterEach(async () => {
        await fs.rm(tmpDir, { recursive: true, force: true });
    });

    it('should add documents correctly', async () => {
        const doc1: VectorDocument = {
            id: '1',
            vector: [1, 0, 0],
            metadata: { name: 'A' }
        };
        await store.add(doc1);
        expect(store.size).toBe(1);
    });

    it('should query and rank results by cosine similarity', async () => {
        const doc1: VectorDocument = {
            id: '1',
            vector: [1, 0, 0],
            metadata: { name: 'A' }
        };
        const doc2: VectorDocument = {
            id: '2',
            vector: [0, 1, 0],
            metadata: { name: 'B' }
        };
        const doc3: VectorDocument = {
            id: '3',
            vector: [0.9, 0.1, 0], // Very close to A
            metadata: { name: 'C' }
        };
        const doc4: VectorDocument = {
            id: '4',
            vector: [0.707, 0.707, 0], // 45 degrees
            metadata: { name: 'D' }
        };

        await store.add(doc1);
        await store.add(doc2);
        await store.add(doc3);
        await store.add(doc4);

        // Query for [1, 0, 0]
        const results = await store.query([1, 0, 0], 3);

        expect(results.length).toBe(3);

        // 1. Exact match
        expect(results[0].document.id).toBe('1');
        expect(results[0].score).toBeCloseTo(1.0);

        // 2. High similarity
        expect(results[1].document.id).toBe('3');

        // 3. Medium similarity (0.707) vs No similarity (0)
        expect(results[2].document.id).toBe('4');
    });

    it('should persist and load data from disk', async () => {
        const doc1: VectorDocument = {
            id: '1',
            vector: [1, 0, 0],
            metadata: { name: 'A' }
        };
        await store.add(doc1);
        await store.save();

        // New instance
        const store2 = new VectorStore(storePath);
        await store2.load();

        expect(store2.size).toBe(1);
        const results = await store2.query([1, 0, 0], 1);
        expect(results[0].document.id).toBe('1');
    });

    it('should handle updates (upsert) correctly', async () => {
        const doc1: VectorDocument = {
            id: '1',
            vector: [1, 0, 0],
            metadata: { name: 'Version 1' }
        };
        await store.add(doc1);

        const doc1V2: VectorDocument = {
            id: '1',
            vector: [0, 1, 0], // Changed vector
            metadata: { name: 'Version 2' }
        };
        await store.add(doc1V2);

        expect(store.size).toBe(1); // Should still be 1 doc

        const results = await store.query([0, 1, 0], 1);
        expect(results[0].document.id).toBe('1');
        expect(results[0].score).toBeCloseTo(1.0);
        expect(results[0].document.metadata.name).toBe('Version 2');
    });
});
