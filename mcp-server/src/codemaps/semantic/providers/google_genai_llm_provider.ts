import { LlmProvider } from "../llm_provider.js";
import { GoogleGenerativeAI, Schema } from "@google/generative-ai";

export class GoogleGenAILlmProvider implements LlmProvider {
    private genAI: GoogleGenerativeAI;
    private model: any;

    constructor(apiKey: string, modelName: string = "gemini-1.5-flash") {
        this.genAI = new GoogleGenerativeAI(apiKey);
        // By default, just initialize the model. We can override generation config per request.
        this.model = this.genAI.getGenerativeModel({ model: modelName });
    }

    async generateText(prompt: string, jsonMode: boolean = false): Promise<string> {
        let generationConfig = {};
        if (jsonMode) {
            generationConfig = { responseMimeType: "application/json" };
        }

        const result = await this.model.generateContent({
            contents: [{ role: "user", parts: [{ text: prompt }] }],
            generationConfig
        });

        return result.response.text();
    }
}
