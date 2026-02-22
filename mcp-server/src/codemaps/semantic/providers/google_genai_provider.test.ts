import { describe, it, expect, vi, beforeEach } from 'vitest';
import { GoogleGenAIEmbeddingProvider } from './google_genai_embedding_provider.js';

// Mock the Google Generative AI SDK
const mockEmbedContent = vi.fn();
const mockGetGenerativeModel = vi.fn();
const mockGoogleGenerativeAI = vi.fn();

vi.mock('@google/generative-ai', () => {
    return {
        GoogleGenerativeAI: vi.fn().mockImplementation(() => ({
            getGenerativeModel: mockGetGenerativeModel
        })),
        TaskType: {
            RETRIEVAL_DOCUMENT: 'RETRIEVAL_DOCUMENT'
        }
    };
});

describe('GoogleGenAIEmbeddingProvider', () => {
    let provider: GoogleGenAIEmbeddingProvider;

    beforeEach(() => {
        vi.clearAllMocks();
        
        // Setup mock chain
        mockGetGenerativeModel.mockReturnValue({
            embedContent: mockEmbedContent
        });

        provider = new GoogleGenAIEmbeddingProvider('fake-api-key', 'test-model');
    });

    it('should initialize with correct config', () => {
        // Validation mostly happens via the mock calls during execution, 
        // but we can verify instantiation didn't throw.
        expect(provider).toBeDefined();
    });

    it('should successfully return embeddings', async () => {
        const mockEmbedding = [0.1, 0.2, 0.3];
        mockEmbedContent.mockResolvedValue({
            embedding: { values: mockEmbedding }
        });

        const result = await provider.embed('hello world');

        expect(result).toEqual(mockEmbedding);
        expect(mockGetGenerativeModel).toHaveBeenCalledWith({ model: 'test-model' });
        expect(mockEmbedContent).toHaveBeenCalledWith({
            content: { role: 'user', parts: [{ text: 'hello world' }] },
            taskType: 'RETRIEVAL_DOCUMENT'
        });
    });

    it('should throw error if embedding is missing in response', async () => {
        mockEmbedContent.mockResolvedValue({
            embedding: null 
        });

        await expect(provider.embed('test')).rejects.toThrow('Failed to generate embedding');
    });

    it('should propagate SDK errors', async () => {
        mockEmbedContent.mockRejectedValue(new Error('API Error'));

        await expect(provider.embed('test')).rejects.toThrow('API Error');
    });
});
