class XconnectOne < Formula
  desc "Standalone XConnect Zero controlled-client CLI"
  homepage "https://github.com/ai-workspace-xstream/XConnect-One"
  license "Apache-2.0"
  depends_on :macos

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/ai-workspace-xstream/XConnect-One/releases/download/v0.1.9/xconnect-macos-arm64"
      sha256 "f934c3e6c9f5de73df22e64763bb90a658c7bbd1f86c93bf897569e02e0607a9"
    else
      url "https://github.com/ai-workspace-xstream/XConnect-One/releases/download/v0.1.9/xconnect-macos-amd64"
      sha256 "42e1d1e03223186140a2cf3ef59f5909c68eb3d5839209365295cee113c7467c"
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
