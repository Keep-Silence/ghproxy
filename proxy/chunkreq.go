package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"ghproxy/config"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/WJQSERVER-STUDIO/go-utils/limitreader"
	"github.com/cloudwego/hertz/pkg/app"
)

func ChunkedProxyRequest(ctx context.Context, c *app.RequestContext, u string, cfg *config.Config, matcher string) {

	var (
		req  *http.Request
		resp *http.Response
		err  error
	)

	go func() {
		<-ctx.Done()
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		if req != nil {
			req.Body.Close()
		}
	}()

	rb := client.NewRequestBuilder(string(c.Request.Method()), u)
	rb.NoDefaultHeaders()
	rb.SetBody(c.Request.BodyStream())
	rb.WithContext(ctx)

	req, err = rb.Build()
	if err != nil {
		HandleError(c, fmt.Sprintf("Failed to create request: %v", err))
		return
	}

	setRequestHeaders(c, req, cfg, matcher)
	AuthPassThrough(c, cfg, req)

	isCache := string(c.Request.Method()) == http.MethodGet
	if isCache {
		if reader, info, err := loadFromCache(http.MethodGet, u); err == nil {
			logDebug("Cache HIT: %s", u)
			c.Header("X-Cache", "HIT")
			c.SetBodyStream(reader, int(info.Size()))
			return
		}
	}

	resp, err = client.Do(req)
	if err != nil {
		HandleError(c, fmt.Sprintf("Failed to send request: %v", err))
		return
	}

	// 错误处理(404)
	if resp.StatusCode == 404 {
		ErrorPage(c, NewErrorWithStatusLookup(404, "Page Not Found (From Github)"))
		return
	}

	var (
		bodySize      int
		contentLength string
		sizelimit     int
	)
	sizelimit = cfg.Server.SizeLimit * 1024 * 1024
	contentLength = resp.Header.Get("Content-Length")
	if contentLength != "" {
		var err error
		bodySize, err = strconv.Atoi(contentLength)
		if err != nil {
			logWarning("%s %s %s %s %s Content-Length header is not a valid integer: %v", c.ClientIP(), c.Method(), c.Path(), c.UserAgent(), c.Request.Header.GetProtocol(), err)
			bodySize = -1
		}
		if err == nil && bodySize > sizelimit {
			finalURL := resp.Request.URL.String()
			err = resp.Body.Close()
			if err != nil {
				logError("Failed to close response body: %v", err)
			}
			c.Redirect(301, []byte(finalURL))
			logWarning("%s %s %s %s %s Final-URL: %s Size-Limit-Exceeded: %d", c.ClientIP(), c.Method(), c.Path(), c.UserAgent(), c.Request.Header.GetProtocol(), finalURL, bodySize)
			return
		}
	}

	// 复制响应头，排除需要移除的 header
	for key, values := range resp.Header {
		if _, shouldRemove := respHeadersToRemove[key]; !shouldRemove {
			for _, value := range values {
				c.Header(key, value)
			}
		}
	}

	switch cfg.Server.Cors {
	case "*":
		c.Header("Access-Control-Allow-Origin", "*")
	case "":
		c.Header("Access-Control-Allow-Origin", "*")
	case "nil":
		c.Header("Access-Control-Allow-Origin", "")
	default:
		c.Header("Access-Control-Allow-Origin", cfg.Server.Cors)
	}

	c.Status(resp.StatusCode)

	bodyReader := resp.Body

	if cfg.RateLimit.BandwidthLimit.Enabled {
		bodyReader = limitreader.NewRateLimitedReader(bodyReader, bandwidthLimit, int(bandwidthBurst), ctx)
	}

	if MatcherShell(u) && matchString(matcher, matchedMatchers) && cfg.Shell.Editor {
		// 判断body是不是gzip
		var compress string
		if resp.Header.Get("Content-Encoding") == "gzip" {
			compress = "gzip"
		}

		logDebug("Use Shell Editor: %s %s %s %s %s", c.ClientIP(), c.Request.Method(), u, c.Request.Header.Get("User-Agent"), c.Request.Header.GetProtocol())
		c.Header("Content-Length", "")

		var reader io.Reader

		reader, _, err = processLinks(bodyReader, compress, string(c.Request.Host()), cfg)
		if isCache {
			var teeBuf io.Reader
			pr, pw := io.Pipe()
			teeBuf = io.TeeReader(reader, pw)
			c.SetBodyStream(pr, -1)

			// 异步写入缓存
			go func() {
				defer pw.Close()
				err := saveToCache(http.MethodGet, u, teeBuf)
				if err != nil {
					logWarning("Cache save failed: %v", err)
				} else {
					logDebug("Cache saved: %s", u)
				}
			}()
			return
		}
		c.SetBodyStream(reader, -1)
		if err != nil {
			logError("%s %s %s %s %s Failed to copy response body: %v", c.ClientIP(), c.Request.Method(), u, c.Request.Header.Get("User-Agent"), c.Request.Header.GetProtocol(), err)
			ErrorPage(c, NewErrorWithStatusLookup(500, fmt.Sprintf("Failed to copy response body: %v", err)))
			return
		}
	} else {
		if isCache {
			var teeBuf io.Reader
			pr, pw := io.Pipe()
			teeBuf = io.TeeReader(bodyReader, pw)
			if contentLength != "" {
				c.SetBodyStream(pr, bodySize)
			}
			c.SetBodyStream(pr, -1)

			// 异步写入缓存
			go func() {
				defer pw.Close()
				err := saveToCache(http.MethodGet, u, teeBuf)
				if err != nil {
					logWarning("Cache save failed: %v", err)
				} else {
					logDebug("Cache saved: %s", u)
				}
			}()
			return
		}
		if contentLength != "" {
			c.SetBodyStream(bodyReader, bodySize)
			return
		}
		c.SetBodyStream(bodyReader, -1)
	}

}

var cacheDir = "~/.ghproxy_cache" // 可配置

func cacheKey(method, url string) string {
	hash := sha256.Sum256([]byte(method + "::" + url))
	return hex.EncodeToString(hash[:])
}

func cachePath(method, url string) string {
	return filepath.Join(cacheDir, cacheKey(method, url))
}

func loadFromCache(method, url string) (io.ReadCloser, os.FileInfo, error) {
	path := cachePath(method, url)
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, info, nil
}

func saveToCache(method, url string, r io.Reader) error {
	path := cachePath(method, url)

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	tmpPath := path + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, r)
	if err != nil {
		os.Remove(tmpPath)
		return err
	}

	return os.Rename(tmpPath, path)
}
