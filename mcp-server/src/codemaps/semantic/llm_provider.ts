export interface LlmProvider {
    /**
     * Generates a text response for the given prompt.
     * @param prompt The prompt to send to the LLM.
     * @param jsonMode If true, requests the LLM to return the response in JSON format.
     * @returns A promise resolving to the text response.
     */
    generateText(prompt: string, jsonMode?: boolean): Promise<string>;
}
