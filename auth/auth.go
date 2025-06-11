package auth

import (
	"context"
	"fmt"
	"ghproxy/config"

	"github.com/WJQSERVER-STUDIO/logger"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/redis/go-redis/v9"
)

var (
	logw       = logger.Logw
	logDump    = logger.LogDump
	logDebug   = logger.LogDebug
	logInfo    = logger.LogInfo
	logWarning = logger.LogWarning
	logError   = logger.LogError
	rdbCtx     context.Context
	rdb        *redis.Client
)

func Init(cfg *config.Config) {
	if cfg.Blacklist.Enabled {
		err := InitBlacklist(cfg)
		if err != nil {
			logError(err.Error())
			return
		}
	}
	if cfg.Whitelist.Enabled {
		err := InitWhitelist(cfg)
		if err != nil {
			logError(err.Error())
			return
		}
	}
	if cfg.Auth.RedisAddr != "" {
		rdbCtx = context.Background()
		rdb = redis.NewClient(&redis.Options{
			Addr:         cfg.Auth.RedisAddr,
			Password:     cfg.Auth.RedisPassword,
			DB:           cfg.Auth.RedisDB,
			MinIdleConns: 1,
		})
		_, err := rdb.Ping(rdbCtx).Result()
		if err != nil {
			panic(err.Error())
		}
	}
	logDebug("Auth Init")
}

func AuthHandler(c *app.RequestContext, cfg *config.Config) (isValid bool, err error) {
	if cfg.Auth.Method == "parameters" {
		isValid, err = AuthParametersHandler(c, cfg)
		return isValid, err
	} else if cfg.Auth.Method == "header" {
		isValid, err = AuthHeaderHandler(c, cfg)
		return isValid, err
	} else if cfg.Auth.Method == "" {
		logError("Auth method not set")
		return true, nil
	} else {
		logError("Auth method not supported %s", cfg.Auth.Method)
		return false, fmt.Errorf("%s", fmt.Sprintf("Auth method %s not supported", cfg.Auth.Method))
	}
}
