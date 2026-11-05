# typed: false
# frozen_string_literal: true

# Homebrew formula template for disk-cleaner-mcp v0.4.0.
# To publish: copy this file into homebrew-tap as Formula/disk-cleaner-mcp.rb,
# then bump `version`, the `url`, and the `sha256` fields on each release.
class DiskCleanerMcp < Formula
  desc "Disk Cleaner MCP — safe, evidence-backed junk cleanup over the Model Context Protocol"
  homepage "https://github.com/CThawngs/Disk-Cleaner-MCP"
  version "0.4.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/CThawngs/Disk-Cleaner-MCP/releases/download/v0.4.0/disk-cleaner-mcp-aarch64-apple-darwin"
      sha256 "7675a392f54ae89e4bac452afd41d95e9fce0a00401885df12c817e4f0ee613e"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/CThawngs/Disk-Cleaner-MCP/releases/download/v0.4.0/disk-cleaner-mcp-x86_64-unknown-linux-gnu"
      sha256 "0c50a3e03aad06c6975a05a7453836cfa843cdf84a6c6109ef201402404b277f"
    end
  end

  def install
    bin.install Dir["disk-cleaner-mcp-*"].first => "disk-cleaner-mcp"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/disk-cleaner-mcp --version")
  end
end
