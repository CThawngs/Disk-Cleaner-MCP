# typed: false
# frozen_string_literal: true

# Homebrew formula template for disk-cleaner-mcp v0.5.0.
# To publish: copy this file into homebrew-tap as Formula/disk-cleaner-mcp.rb,
// then bump `version`, the `url`, and the `sha256` fields on each release.
class DiskCleanerMcp < Formula
  desc "Disk Cleaner MCP — safe, evidence-backed junk cleanup over the Model Context Protocol"
  homepage "https://github.com/CThawngs/Disk-Cleaner-MCP"
  version "0.5.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/CThawngs/Disk-Cleaner-MCP/releases/download/v0.5.0/disk-cleaner-mcp-aarch64-apple-darwin"
      sha256 "3ae141b96182f99d21f9dd1bb4ccf87fb4475db583e62b91a0266016331299d0"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/CThawngs/Disk-Cleaner-MCP/releases/download/v0.5.0/disk-cleaner-mcp-x86_64-unknown-linux-gnu"
      sha256 "d968fd6e051af86785acd188d0bf6dd9bf2594e7205d23dfdc2a5a6ac9024fea"
    end
  end

  def install
    bin.install Dir["disk-cleaner-mcp-*"].first => "disk-cleaner-mcp"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/disk-cleaner-mcp --version")
  end
end
