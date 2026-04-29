package router

import (
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var srv = server.NewMCPServer("demo", "1.0.0")

func init() {
	srv.AddTool(mcp.Tool{}, nil)
}

func Register(api Router, mcpHandler *server.StreamableHTTPServer) {
	api.Any("/mcp", AuthRequired(), func(c *Context) {
		mcpHandler.ServeHTTP(c)
	})

	api.Any("/mcp_message", AuthRequired(), func(c *Context) {
		mcpHandler.ServeHTTP(c)
	})
}
