package mcp

import (
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var srv = server.NewMCPServer(
	"Nginx",
	"1.0.0",
)

func register(tool mcp.Tool, handler any) {
	srv.AddTool(tool, handler)
}
