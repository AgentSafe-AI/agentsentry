package analyzer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPNPMRegistryClient_AllowsBooleanBundleDependencies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"name": "demo",
			"version": "1.0.0",
			"scripts": {"postinstall": "node install.js"},
			"bundleDependencies": false
		}`))
	}))
	t.Cleanup(server.Close)

	client := &httpNPMRegistryClient{
		http:    server.Client(),
		baseURL: server.URL,
	}

	got, err := client.FetchVersion(context.Background(), "demo", "1.0.0")
	require.NoError(t, err)
	assert.Equal(t, "node install.js", got.Scripts["postinstall"])
	assert.Empty(t, got.BundleDependencies)
}
