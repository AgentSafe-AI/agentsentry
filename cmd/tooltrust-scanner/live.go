package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/kballard/go-shellquote"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	mcpgo "github.com/mark3labs/mcp-go/mcp"
	"github.com/pterm/pterm"

	localmcp "github.com/AgentSafe-AI/tooltrust-scanner/pkg/adapter/mcp"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

func scanLiveServer(ctx context.Context, serverCmd string) ([]model.UnifiedTool, error) {
	args, err := shellquote.Split(serverCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server command: %w", err)
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("empty server command")
	}

	importTransport := true
	_ = importTransport // To avoid unused variable issue during plan stage if I mess up imports

	spinner, err := pterm.DefaultSpinner.Start("🔌 Connecting to live MCP server: " + serverCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to start spinner: %w", err)
	}

	// Create a cancelable context to forcefully kill the sub-process on exit.
	execCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	stdioTransport := transport.NewStdioWithOptions(args[0], nil, args[1:])
	if startErr := stdioTransport.Start(execCtx); startErr != nil {
		if execCtx.Err() == context.DeadlineExceeded {
			spinner.Fail("Connection to MCP server timed out after 30 seconds.")
			pterm.Error.Println("❌ Error: Connection to MCP server timed out after 30 seconds.")
			return nil, fmt.Errorf("connection to MCP server timed out: %w", startErr)
		}
		spinner.Fail("Failed to start transport")
		return nil, fmt.Errorf("failed to start transport: %w", startErr)
	}

	c := client.NewClient(stdioTransport)
	defer c.Close() //nolint:errcheck // closing client on exit, error is acceptable

	initReq := mcpgo.InitializeRequest{}
	initReq.Params.ProtocolVersion = "2024-11-05"
	initReq.Params.ClientInfo = mcpgo.Implementation{
		Name:    "tooltrust-scanner",
		Version: "1.0.0",
	}

	_, err = c.Initialize(ctx, initReq)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			spinner.Fail("Connection to MCP server timed out after 30 seconds.")
			pterm.Error.Println("❌ Error: Connection to MCP server timed out after 30 seconds.")
			return nil, fmt.Errorf("initialization timed out: %w", err)
		}
		spinner.Fail("Initialization failed")
		return nil, fmt.Errorf("initialization failed: %w", err)
	}

	listReq := mcpgo.ListToolsRequest{}
	resp, err := c.ListTools(ctx, listReq)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			spinner.Fail("Connection to MCP server timed out after 30 seconds.")
			pterm.Error.Println("❌ Error: Connection to MCP server timed out after 30 seconds.")
			return nil, fmt.Errorf("tools/list map timed out: %w", err)
		}
		spinner.Fail("Failed to fetch tools")
		return nil, fmt.Errorf("tools/list map failed: %w", err)
	}

	spinner.Success("Connected and tools fetched!")

	// We serialize the response back to JSON so we can use our existing adapter,
	// which also runs the inference rules for permissions.
	// Since mcp-go uses `mcpgo.Tool` and we expect `mcp.Tool`, we wrap it.
	type dummyResponse struct {
		Tools []mcpgo.Tool `json:"tools"`
	}
	payload := dummyResponse{Tools: resp.Tools}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tools: %w", err)
	}

	adapter := localmcp.NewAdapter()
	tools, err := adapter.Parse(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tools: %w", err)
	}
	return tools, nil
}
