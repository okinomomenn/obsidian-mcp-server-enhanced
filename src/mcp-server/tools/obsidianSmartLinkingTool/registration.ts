/**
 * @fileoverview Registration configuration for the Obsidian Smart Linking tool.
 */

import { Tool } from "@modelcontextprotocol/sdk/types.js";

/**
 * Tool definition for intelligent link suggestions and smart linking in Obsidian.
 */
export const obsidianSmartLinkingToolDefinition: Tool = {
  name: "obsidian_smart_linking",
  description: `Provide intelligent link suggestions and smart linking capabilities for Obsidian notes.

Key capabilities:
- Suggest relevant notes to link based on content similarity
- Find potential link opportunities in existing text
- Analyze content for linkable concepts and entities
- Suggest backlinks based on semantic relationships
- Generate link recommendations for new content
- Find broken or missing links in notes
- Recommend tags based on content analysis

Perfect for improving note interconnectedness, discovering related content, and building a more cohesive knowledge graph.
Uses content analysis, keyword matching, and semantic relationships to make intelligent suggestions.`,

  inputSchema: {
    type: "object",
    properties: {
      operation: {
        type: "string",
        enum: [
          "suggest_links_for_content",
          "find_link_opportunities", 
          "analyze_linkable_concepts",
          "suggest_backlinks",
          "recommend_tags",
          "find_broken_links",
          "get_link_suggestions"
        ],
        description: "Type of smart linking operation to perform",
      },
      filePath: {
        type: "string",
        description: "【必須（operation が find_link_opportunities / suggest_backlinks / find_broken_links のとき。suggest_links_for_content / analyze_linkable_concepts / recommend_tags / get_link_suggestions では filePath か content のいずれかが必須）】Path to the target note",
      },
      content: {
        type: "string",
        description: "【必須（operation が suggest_links_for_content / analyze_linkable_concepts / recommend_tags / get_link_suggestions で filePath を渡さないとき）】Text content to analyze for link suggestions (alternative to filePath)",
      },
      maxSuggestions: {
        type: "number",
        minimum: 1,
        maximum: 50,
        default: 10,
        description: "Maximum number of suggestions to return",
      },
      similarityThreshold: {
        type: "number",
        minimum: 0.1,
        maximum: 1.0,
        default: 0.3,
        description: "Minimum similarity score for suggestions (0.1-1.0)",
      },
      includeExistingLinks: {
        type: "boolean",
        default: false,
        description: "Whether to include notes that are already linked",
      },
      contextWindow: {
        type: "number",
        minimum: 50,
        maximum: 500,
        default: 150,
        description: "Number of characters around potential link locations to analyze",
      },
      excludeFolders: {
        type: "array",
        items: {
          type: "string"
        },
        description: "Folders to exclude from link suggestions",
      },
      includeTagSuggestions: {
        type: "boolean",
        default: true,
        description: "Whether to include tag-based suggestions",
      },
    },
    required: ["operation"],
    additionalProperties: false,
  },
};