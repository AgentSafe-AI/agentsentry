# Homebrew Formula for ToolTrust Scanner
# Install: brew install --formula "https://raw.githubusercontent.com/AgentSafe-AI/tooltrust-scanner/main/Formula/tooltrust-scanner.rb"
#
# To update to a new release vX.Y.Z:
#   1. Create the git tag and push: git tag vX.Y.Z && git push origin vX.Y.Z
#   2. curl -sL https://github.com/AgentSafe-AI/tooltrust-scanner/archive/refs/tags/vX.Y.Z.tar.gz | shasum -a 256
#   3. Update version and sha256 below

class TooltrustScanner < Formula
  desc "Security scanner for AI agent tool definitions"
  homepage "https://github.com/AgentSafe-AI/tooltrust-scanner"
  version "0.3.8"
  url "https://github.com/AgentSafe-AI/tooltrust-scanner/archive/refs/tags/v#{version}.tar.gz"
  sha256 "1a48e9acf4e7d3e66f6a526b28e439f5aab455ba6e5e4ed9f51248513bf3392e"
  license "MIT"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w -X main.version=#{version}"), "./cmd/tooltrust-scanner"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/tooltrust-scanner version")
  end
end
