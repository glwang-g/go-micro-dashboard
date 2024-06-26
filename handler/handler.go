package handler

import (
	"github.com/gin-gonic/gin"
	"github.com/go-micro/dashboard/config"
	"github.com/go-micro/dashboard/docs"
	"github.com/go-micro/dashboard/handler/account"
	handlerclient "github.com/go-micro/dashboard/handler/client"
	"github.com/go-micro/dashboard/handler/registry"
	"github.com/go-micro/dashboard/handler/route"
	"github.com/go-micro/dashboard/handler/statistics"
	"github.com/go-micro/dashboard/web"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"go-micro.dev/v4/client"
)

type Options struct {
	Client client.Client
	Router *gin.Engine
}

func Register(opts Options) error {
	router := opts.Router
	if cfg := config.GetServerConfig(); cfg.Env == config.EnvDev {
		docs.SwaggerInfo.Host = cfg.Swagger.Host
		docs.SwaggerInfo.BasePath = cfg.Swagger.Base
		router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	}
	if err := web.RegisterRoute(router); err != nil {
		return err
	}
	if cfg := config.GetServerConfig().CORS; cfg.Enable {
		router.Use(route.CorsHandler(cfg.Origin))
	}
	for _, r := range []route.Registrar{
		account.NewRouteRegistrar(),
		handlerclient.NewRouteRegistrar(opts.Client, opts.Client.Options().Registry),
		registry.NewRouteRegistrar(opts.Client.Options().Registry),
		statistics.NewRouteRegistrar(opts.Client.Options().Registry),
	} {
		r.RegisterRoute(router.Group(""))
	}
	return nil
}
