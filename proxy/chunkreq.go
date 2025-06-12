package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"ghproxy/config"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/WJQSERVER-STUDIO/go-utils/limitreader"
	"github.com/cloudwego/hertz/pkg/app"
)

var keyNameMap = make(map[string]string)

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

	cacheUrl := u
	parseUrl, err := url.Parse(u)
	if err == nil {
		query := parseUrl.Query()
		query.Del(cfg.Auth.Key)
		parseUrl.RawQuery = query.Encode()
		cacheUrl = parseUrl.String()
	}

	isCache := string(c.Request.Method()) == http.MethodGet
	if filename, ok := keyNameMap[cacheUrl]; ok && isCache {
		if reader, info, err := loadFromCache(http.MethodGet, cacheUrl); err == nil {
			logDebug("Cache HIT: %s", u)
			buf := make([]byte, 512)
			n, _ := reader.Read(buf)
			contentType := http.DetectContentType(buf[:n])
			reader.Seek(0, 0)

			c.Header("X-Cache", "HIT")
			c.Header("Content-Type", contentType)
			c.Header("Content-Disposition", "attachment; filename="+filename)
			c.Header("Content-Length", strconv.FormatInt(info.Size(), 10))
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

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		logError("%s %s %s %s %s Failed to copy response body: %v", c.ClientIP(), c.Request.Method(), u, c.Request.Header.Get("User-Agent"), c.Request.Header.GetProtocol(), err)
		ErrorPage(c, NewErrorWithStatusLookup(500, fmt.Sprintf("Failed to copy response body: %v", err)))
	}

	if isCache {
		go func() {
			// 异步写入缓存
			fileName := DetectFilename(resp)
			keyNameMap[cacheUrl] = fileName
			err := saveToCache(http.MethodGet, cacheUrl, bodyBytes)
			if err != nil {
				logWarning("Cache save failed: %v", err)
			} else {
				logDebug("Cache saved: %s", cacheUrl)
			}
		}()
	}

	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
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
		c.SetBodyStream(reader, -1)
		if err != nil {
			logError("%s %s %s %s %s Failed to copy response body: %v", c.ClientIP(), c.Request.Method(), u, c.Request.Header.Get("User-Agent"), c.Request.Header.GetProtocol(), err)
			ErrorPage(c, NewErrorWithStatusLookup(500, fmt.Sprintf("Failed to copy response body: %v", err)))
			return
		}
	} else {
		if contentLength != "" {
			c.SetBodyStream(bodyReader, bodySize)
			return
		}
		c.SetBodyStream(bodyReader, -1)
	}
}

var cacheDir = os.TempDir()

func cacheKey(method, url string) string {
	hash := sha256.Sum256([]byte(method + "::" + url))
	return hex.EncodeToString(hash[:])
}

func cachePath(method, urlStr string) string {
	return filepath.Join(cacheDir, cacheKey(method, urlStr))
}

func loadFromCache(method, url string) (*os.File, os.FileInfo, error) {
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

func saveToCache(method, url string, r []byte) error {
	path := cachePath(method, url)

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	tmpPath := path + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return err
	}

	_, err = f.Write(r)
	if err != nil {
		os.Remove(tmpPath)
		return err
	}

	f.Close()
	return os.Rename(tmpPath, path)
}

// 提取 Content-Disposition 中的 filename=
func getFilenameFromContentDisposition(cd string) string {
	// RFC6266 支持的格式：filename="xxx.ext"
	re := regexp.MustCompile(`(?i)filename="?([^\";]+)"?`)
	matches := re.FindStringSubmatch(cd)
	if len(matches) >= 2 {
		return matches[1]
	}
	return "unknown_filename"
}

func filenameFromURL(rawurl string) string {
	u, err := url.Parse(rawurl)
	if err != nil {
		return "unknown"
	}
	return path.Base(u.Path)
}

func DetectFilename(resp *http.Response) string {
	cd := resp.Header.Get("Content-Disposition")
	name := getFilenameFromContentDisposition(cd)
	if name != "unknown_filename" {
		return name
	}
	return filenameFromURL(resp.Request.URL.String())
}
