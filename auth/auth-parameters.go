package auth

import (
	"fmt"
	"ghproxy/config"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
)

func AuthParametersHandler(c *app.RequestContext, cfg *config.Config) (isValid bool, err error) {
	if !cfg.Auth.Enabled {
		return true, nil
	}

	var authToken string
	if cfg.Auth.Key != "" {
		authToken = c.Query(cfg.Auth.Key)
	} else {
		authToken = c.Query("auth_token")
	}

	logDebug("%s %s %s %s %s AUTH_TOKEN: %s", c.ClientIP(), c.Method(), string(c.Path()), c.Request.Header.UserAgent(), c.Request.Header.GetProtocol(), authToken)

	if authToken == "" {
		return false, fmt.Errorf("Auth token not found")
	}

	if strings.HasPrefix(authToken, "Bearer ") {
		authToken = "token:" + strings.TrimPrefix(authToken, "Bearer ")
	}
	if rdb != nil && rdb.Exists(rdbCtx, authToken).Val() > 0 {
		return true, nil
	}
	isValid = authToken == cfg.Auth.Token
	if !isValid {
		return false, fmt.Errorf("Auth token invalid")
	}

	return isValid, nil
}
