package sourcedetect

import "regexp"

type SDKSignature struct {
	Language        string
	FileExtensions  []string
	ImportPatterns  []*regexp.Regexp
	InitPatterns    []*regexp.Regexp
	ToolDefPatterns []*regexp.Regexp
}

var signatures = []SDKSignature{
	{
		Language:       "go",
		FileExtensions: []string{".go"},
		ImportPatterns: []*regexp.Regexp{
			regexp.MustCompile(`"github\.com/modelcontextprotocol/go-sdk(?:/mcp)?"`),
			regexp.MustCompile(`"github\.com/mark3labs/mcp-go/server"`),
		},
		InitPatterns: []*regexp.Regexp{
			regexp.MustCompile(`\bmcp\.NewServer\s*\(`),
			regexp.MustCompile(`\bserver\.NewMCPServer\s*\(`),
		},
		ToolDefPatterns: []*regexp.Regexp{
			regexp.MustCompile(`\b(?:server\.)?AddTool\s*\(`),
		},
	},
	{
		Language:       "python",
		FileExtensions: []string{".py"},
		ImportPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?m)^\s*from\s+mcp\.server\.fastmcp\s+import\s+FastMCP\b`),
			regexp.MustCompile(`(?m)^\s*import\s+mcp\.server\.fastmcp\b`),
		},
		InitPatterns: []*regexp.Regexp{
			regexp.MustCompile(`\bFastMCP\s*\(`),
		},
		ToolDefPatterns: []*regexp.Regexp{
			regexp.MustCompile(`@\w+\.tool\s*\(`),
		},
	},
	{
		Language:       "typescript",
		FileExtensions: []string{".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"},
		ImportPatterns: []*regexp.Regexp{
			regexp.MustCompile(`["']@modelcontextprotocol/sdk`),
		},
		InitPatterns: []*regexp.Regexp{
			regexp.MustCompile(`\bnew\s+McpServer\s*\(`),
		},
		ToolDefPatterns: []*regexp.Regexp{
			regexp.MustCompile(`\.registerTool\s*\(`),
		},
	},
}

func signatureForExt(ext string) []SDKSignature {
	var out []SDKSignature
	for _, sig := range signatures {
		for _, candidate := range sig.FileExtensions {
			if candidate == ext {
				out = append(out, sig)
				break
			}
		}
	}
	return out
}
