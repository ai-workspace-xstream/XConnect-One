class XconnectOne < Formula
  desc "Standalone XConnect Zero controlled-client CLI"
  homepage "https://github.com/ai-workspace-xstream/XConnect-One"
  license "Apache-2.0"
  depends_on :macos

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/ai-workspace-xstream/XConnect-One/releases/download/v0.1.11/xconnect-macos-arm64"
      sha256 "a2ab05a6cfd625a460128be76072caf85c2bfb250d37e75087875788650ca0b5"
    else
      url "https://github.com/ai-workspace-xstream/XConnect-One/releases/download/v0.1.11/xconnect-macos-amd64"
      sha256 "f1e735934dc224724f2fdfa7dd9ee34cc1a6f5b86caf101026d9aa280cc35a38"
    end
  end

  def install
    asset = Hardware::CPU.arm? ? "xconnect-macos-arm64" : "xconnect-macos-amd64"
    bin.install asset => "xconnect"
  end

  test do
    assert_match '"joined": false', shell_output("#{bin}/xconnect status --state-dir #{testpath}/state")
  end
end
