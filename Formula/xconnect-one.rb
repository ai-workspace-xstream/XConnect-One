class XconnectOne < Formula
  desc "Standalone XConnect Zero controlled-client CLI"
  homepage "https://github.com/ai-workspace-xstream/XConnect-One"
  license "Apache-2.0"
  depends_on :macos

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/ai-workspace-xstream/XConnect-One/releases/download/v0.1.10/xconnect-macos-arm64"
      sha256 "469e836f602501e464ff795526a92c50c9ee163b5e1a3d114d82c5c818bdeaf8"
    else
      url "https://github.com/ai-workspace-xstream/XConnect-One/releases/download/v0.1.10/xconnect-macos-amd64"
      sha256 "c7815322d5ae96d6d1625ece78a03e7ba4f10f422d6fa1983acc9e2dd1516117"
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
