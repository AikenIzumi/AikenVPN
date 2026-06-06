// Package nettest provides ping and speed-test utilities for VPN diagnostics.
package nettest

import (
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"sort"
	"time"
)

// PingResult holds the result of a ping test
type PingResult struct {
	Host   string  `json:"host"`
	Min    float64 `json:"min_ms"`
	Avg    float64 `json:"avg_ms"`
	Max    float64 `json:"max_ms"`
	Loss   float64 `json:"loss_pct"`
	Jitter float64 `json:"jitter_ms"`
	Error  string  `json:"error,omitempty"`
}

// SpeedResult holds the result of a speed test
type SpeedResult struct {
	DownloadMbps float64 `json:"download_mbps"`
	UploadMbps   float64 `json:"upload_mbps"`
	PingMs       float64 `json:"ping_ms"`
	Server       string  `json:"server"`
	Error        string  `json:"error,omitempty"`
}

// Ping measures round-trip latency to host by establishing TCP connections.
// count = number of probes, timeout per probe.
func Ping(host string, count int, timeout time.Duration) PingResult {
	if count <= 0 {
		count = 5
	}
	if timeout == 0 {
		timeout = 3 * time.Second
	}

	// Resolve port: try 80, then 443
	addr := net.JoinHostPort(host, "80")

	var rtts []float64
	lost := 0

	for i := 0; i < count; i++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", addr, timeout)
		elapsed := time.Since(start).Seconds() * 1000

		if err != nil {
			// Try port 443
			start = time.Now()
			conn, err = net.DialTimeout("tcp", net.JoinHostPort(host, "443"), timeout)
			elapsed = time.Since(start).Seconds() * 1000
		}

		if err != nil {
			lost++
		} else {
			conn.Close()
			rtts = append(rtts, elapsed)
		}
		if i < count-1 {
			time.Sleep(200 * time.Millisecond)
		}
	}

	if len(rtts) == 0 {
		return PingResult{
			Host:  host,
			Loss:  100,
			Error: fmt.Sprintf("100%% потерь — хост недоступен"),
		}
	}

	sort.Float64s(rtts)
	min := rtts[0]
	max := rtts[len(rtts)-1]
	sum := 0.0
	for _, v := range rtts {
		sum += v
	}
	avg := sum / float64(len(rtts))

	// Jitter = mean absolute deviation
	jitterSum := 0.0
	for _, v := range rtts {
		jitterSum += math.Abs(v - avg)
	}
	jitter := jitterSum / float64(len(rtts))

	return PingResult{
		Host:   host,
		Min:    round2(min),
		Avg:    round2(avg),
		Max:    round2(max),
		Loss:   round2(float64(lost) / float64(count) * 100),
		Jitter: round2(jitter),
	}
}

// SpeedTest runs a quick download+upload speed test using public CDN endpoints.
// It downloads a ~10MB file and uploads a ~1MB payload.
func SpeedTest() SpeedResult {
	const downloadURL = "https://speed.cloudflare.com/__down?bytes=10000000"
	const uploadURL   = "https://speed.cloudflare.com/__up"

	client := &http.Client{Timeout: 30 * time.Second}

	// ── Ping (latency to speed test server) ──────────────────
	pingResult := Ping("speed.cloudflare.com", 4, 3*time.Second)

	// ── Download ─────────────────────────────────────────────
	dlStart := time.Now()
	resp, err := client.Get(downloadURL)
	if err != nil {
		return SpeedResult{Error: "download error: " + err.Error(), Server: "Cloudflare"}
	}
	n, err := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	dlDuration := time.Since(dlStart).Seconds()
	if err != nil || dlDuration == 0 {
		return SpeedResult{Error: "download read error", Server: "Cloudflare"}
	}
	dlMbps := float64(n) * 8 / dlDuration / 1_000_000

	// ── Upload ───────────────────────────────────────────────
	pr, pw := io.Pipe()
	go func() {
		// Write ~1 MB of zeros
		buf := make([]byte, 4096)
		total := 0
		for total < 1_000_000 {
			pw.Write(buf)
			total += len(buf)
		}
		pw.Close()
	}()
	ulStart := time.Now()
	req, _ := http.NewRequest("POST", uploadURL, pr)
	req.Header.Set("Content-Type", "application/octet-stream")
	ulResp, err := client.Do(req)
	ulDuration := time.Since(ulStart).Seconds()
	if err == nil {
		ulResp.Body.Close()
	}

	ulMbps := 0.0
	if ulDuration > 0 {
		ulMbps = 1_000_000 * 8 / ulDuration / 1_000_000
	}

	return SpeedResult{
		DownloadMbps: round2(dlMbps),
		UploadMbps:   round2(ulMbps),
		PingMs:       pingResult.Avg,
		Server:       "Cloudflare",
	}
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}
