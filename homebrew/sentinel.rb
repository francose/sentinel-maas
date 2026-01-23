# Homebrew Formula for Sentinel
# To install: brew install --build-from-source ./homebrew/sentinel.rb
# Or create a tap: brew tap yourusername/sentinel && brew install sentinel

class Sentinel < Formula
  desc "Local Monitoring-as-a-Service agent that gives AI 'Eyes' and 'Hands'"
  homepage "https://github.com/yourusername/sentinel"
  version "1.1.0"
  license "MIT"

  # For local development, use the local path
  # For distribution, replace with:
  # url "https://github.com/yourusername/sentinel/archive/refs/tags/v1.1.0.tar.gz"
  # sha256 "REPLACE_WITH_ACTUAL_SHA256"
  
  url "file://#{HOMEBREW_CACHE}/sentinel-source", using: :nounzip
  
  depends_on "go" => :build

  def install
    # Build the binary
    system "go", "build", *std_go_args(ldflags: "-s -w -X main.Version=#{version}"), "-o", bin/"sentinel", "main.go"
    
    # Install config template
    (etc/"sentinel").mkpath
    (etc/"sentinel/config.yaml.example").write default_config
  end

  def post_install
    # Create config file if it doesn't exist
    config_file = etc/"sentinel/config.yaml"
    unless config_file.exist?
      config_file.write default_config
      chmod 0644, config_file
    end
  end

  def default_config
    <<~EOS
      # Sentinel Configuration File
      # #{etc}/sentinel/config.yaml

      agent_id: "SENTINEL-#{`hostname`.strip}"

      thresholds:
        thermal_warning: 75.0    # Celsius - triggers warning
        thermal_critical: 88.0   # Celsius - triggers critical alert
        cpu_warning: 80.0        # Percent
        cpu_critical: 95.0       # Percent
        memory_warning: 80.0     # Percent
        memory_critical: 95.0    # Percent

      webhook:
        url: ""                  # e.g., "https://your-server.com/api/telemetry"
        interval_seconds: 60     # How often to send telemetry in daemon mode
        enabled: false

      # IPs to block (managed by --block-ip/--unblock-ip)
      blocked_ips: []
    EOS
  end

  def caveats
    <<~EOS
      Sentinel requires root privileges for:
        - Reading thermal sensors (powermetrics)
        - Managing firewall rules (pfctl)
        - Killing processes owned by other users

      Usage:
        sudo sentinel              # TUI mode
        sudo sentinel --json       # JSON telemetry output
        sudo sentinel --kill PID   # Kill a process
        sudo sentinel --block-ip IP   # Block an IP address
        sudo sentinel --webhook URL   # Send telemetry to webhook
        sudo sentinel --daemon     # Run as background daemon

      Config file location: #{etc}/sentinel/config.yaml

      To run as a launch daemon (fleet mode):
        sudo brew services start sentinel
    EOS
  end

  # LaunchDaemon for daemon mode
  service do
    run [opt_bin/"sentinel", "--daemon", "--config", etc/"sentinel/config.yaml"]
    keep_alive true
    require_root true
    log_path var/"log/sentinel.log"
    error_log_path var/"log/sentinel.error.log"
  end

  test do
    assert_match "Sentinel v#{version}", shell_output("#{bin}/sentinel --version")
  end
end
