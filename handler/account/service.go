package account

import (
	"log"
	"time"
	"os"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/render"
	"github.com/go-micro/dashboard/config"
	"github.com/go-micro/dashboard/handler/route"

	xormadapter "github.com/casbin/xorm-adapter/v2"
    _ "github.com/go-sql-driver/mysql"
)

type service struct{}

func NewRouteRegistrar() route.Registrar {
	return service{}
}

func (s service) RegisterRoute(router gin.IRoutes) {
	router.POST("/api/account/login", s.Login)
	router.Use(route.AuthRequired()).GET("/api/account/profile", s.Profile)
}

type loginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type loginResponse struct {
	Token string `json:"token" binding:"required"`
}

// @Tags Account
// @ID account_login
// @Param	input	body		loginRequest	true		"request"
// @Success 200 	{object}	loginResponse	"success"
// @Failure 400 	{object}	string
// @Failure 401 	{object}	string
// @Failure 500		{object}	string
// @Router /api/account/login [post]
func (s *service) Login(ctx *gin.Context) {
	var req loginRequest
	if err := ctx.ShouldBindJSON(&req); nil != err {
		ctx.Render(400, render.String{Format: err.Error()})
		return
	}
	if req.Username != config.GetServerConfig().Auth.Username ||
		req.Password != config.GetServerConfig().Auth.Password {
		ctx.Render(400, render.String{Format: "incorrect username or password"})
		return
	}
	claims := jwt.StandardClaims{
		Subject:   req.Username,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(config.GetAuthConfig().TokenExpiration).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(config.GetAuthConfig().TokenSecret))
	if err != nil {
		ctx.Render(400, render.String{Format: err.Error()})
		return
	}


	if d, err := ValidationAuthority("admin", "data2", "write"); nil != err||!d {
		log.Printf("ERROR:{},{}", d, err)
		ctx.Render(401, render.String{Format: err.Error()})
		return
	}

	ctx.JSON(200, loginResponse{Token: signedToken})
}

type profileResponse struct {
	Name string `json:"name"`
}

// @Security ApiKeyAuth
// @Tags Account
// @ID account_profile
// @Success 200 	{object}	profileResponse	"success"
// @Failure 400 	{object}	string
// @Failure 401 	{object}	string
// @Failure 500		{object}	string
// @Router /api/account/profile [get]
func (s *service) Profile(ctx *gin.Context) {
	ctx.JSON(200, profileResponse{Name: config.GetAuthConfig().Username})
}
 
// 使用Gorm验证访问权限
func ValidationAuthority(sub string, obj string, act string) (bool, error) {
	a, err := xormadapter.NewAdapter("mysql", "root:123456@tcp(127.0.0.1:3306)/")
	if err != nil {
		log.Fatalf("error: adapter: %s", err)
	}

	m, err := model.NewModelFromString(`
	[request_definition]
	r = sub, obj, act

	[policy_definition]
	p = sub, obj, act

	[policy_effect]
	e = some(where (p.eft == allow))

	[matchers]
	m = r.sub == p.sub && r.obj == p.obj && r.act == p.act 
	`)
	if err != nil {
		log.Fatalf("error: model: %s", err)
	}
	e, _ := casbin.NewEnforcer(m, a)
	
	a.LoadPolicy(m)
	log.Printf("Actions:{}", e.GetAllActions())
  	return e.Enforce(sub, obj, act)
}

func fileExist(fileName string) bool {
	_, err := os.Stat(fileName)
	if err == nil { return true}; 
	if os.IsNotExist(err) { return false}
	return false
}