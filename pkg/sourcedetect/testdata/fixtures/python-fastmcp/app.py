from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def hello():
    return "hi"
