package auth

import (
	"encoding/json"
	"errors"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pufferpanel/pufferpanel/v3"
	"github.com/pufferpanel/pufferpanel/v3/config"
	"github.com/pufferpanel/pufferpanel/v3/middleware"
	"github.com/pufferpanel/pufferpanel/v3/models"
	"github.com/pufferpanel/pufferpanel/v3/response"
	"github.com/pufferpanel/pufferpanel/v3/scopes"
	"github.com/pufferpanel/pufferpanel/v3/services"
	"log"
	"net/http"
	"time"
)

type CloudflareIdentity struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

func LoginPost(c *gin.Context) {
	db := middleware.GetDatabase(c)
	us := &services.User{DB: db}

	log.Println(config.CloudflareGetIdentity.Value())
	httpRequest, err := http.NewRequest("GET", config.CloudflareGetIdentity.Value(), nil)
	if response.HandleError(c, err, http.StatusInternalServerError) {
		return
	}

	cookie, err := c.Cookie("CF_Authorization")
	if response.HandleError(c, err, http.StatusBadRequest) {
		return
	}

	httpRequest.AddCookie(&http.Cookie{
		Name:  "CF_Authorization",
		Value: cookie,
	})

	httpResponse, err := http.DefaultClient.Do(httpRequest)
	if response.HandleError(c, err, http.StatusInternalServerError) {
		return
	}

	if httpResponse.StatusCode != http.StatusOK {
		log.Println("Invalid response from cloudflare", httpResponse.StatusCode)
		log.Println(httpRequest)
		log.Println(httpResponse)
		response.HandleError(c, errors.New("invalid cloudflare response"), http.StatusUnauthorized)
		return
	}

	var identity CloudflareIdentity
	err = json.NewDecoder(httpResponse.Body).Decode(&identity)
	if response.HandleError(c, err, http.StatusInternalServerError) {
		return
	}

	user, err := us.Get(identity.Email)
	if user == nil {
		response.HandleError(c, errors.New("invalid user"), http.StatusUnauthorized)
		return
	}

	if response.HandleError(c, err, http.StatusBadRequest) {
		return
	}

	createSession(c, user)
}

func OtpPost(c *gin.Context) {
	db := middleware.GetDatabase(c)
	us := &services.User{DB: db}

	request := &OtpRequestData{}

	err := c.BindJSON(request)
	if response.HandleError(c, err, http.StatusBadRequest) {
		return
	}

	userSession := sessions.Default(c)
	email := userSession.Get("user").(string)
	timestamp := userSession.Get("time").(int64)

	if email == "" {
		response.HandleError(c, pufferpanel.ErrInvalidSession, http.StatusBadRequest)
		return
	}

	if timestamp < time.Now().Unix()-300 {
		userSession.Clear()
		_ = userSession.Save()
		response.HandleError(c, pufferpanel.ErrSessionExpired, http.StatusBadRequest)
		return
	}

	user, err := us.ValidOtp(email, request.Token)
	if response.HandleError(c, err, http.StatusBadRequest) {
		return
	}

	createSession(c, user)
}

func PasskeyStart(c *gin.Context) {
	db := middleware.GetDatabase(c)
	us := &services.User{DB: db}

	request := &PasskeyLoginRequest{}

	err := c.BindJSON(request)
	if response.HandleError(c, err, http.StatusBadRequest) {
		return
	}

	challenge, sessionData, err := us.StartPasskeyLogin(request.Email)
	if errors.Is(err, pufferpanel.ErrInvalidCredentials) {
		response.HandleError(c, err, http.StatusBadRequest)
		return
	}
	if response.HandleError(c, err, http.StatusInternalServerError) {
		return
	}

	sessionDataJson, err := json.Marshal(sessionData)
	if response.HandleError(c, err, http.StatusInternalServerError) {
		return
	}

	userSession := sessions.Default(c)
	userSession.Set("user", request.Email)
	userSession.Set("passkeyLogin", sessionDataJson)
	err = userSession.Save()
	if response.HandleError(c, err, http.StatusInternalServerError) {
		return
	}

	c.JSON(http.StatusOK, challenge)
}

func PasskeyFinish(c *gin.Context) {
	db := middleware.GetDatabase(c)
	us := &services.User{DB: db}

	sessionData := webauthn.SessionData{}

	userSession := sessions.Default(c)
	email := userSession.Get("user").(string)
	sessionDataJson := userSession.Get("passkeyLogin").([]byte)
	err := json.Unmarshal(sessionDataJson, &sessionData)
	if response.HandleError(c, err, http.StatusInternalServerError) {
		return
	}

	user, err := us.ValidatePasskeyLogin(email, c.Request, sessionData)
	if errors.Is(err, pufferpanel.ErrInvalidCredentials) {
		response.HandleError(c, err, http.StatusBadRequest)
		return
	}
	if response.HandleError(c, err, http.StatusInternalServerError) {
		return
	}

	createSession(c, user)
}

func createSession(c *gin.Context, user *models.User) {
	db := middleware.GetDatabase(c)
	ps := &services.Permission{DB: db}
	ss := &services.Session{DB: db}

	perms, err := ps.GetForUserAndServer(user.ID, "")
	if response.HandleError(c, err, http.StatusInternalServerError) {
		return
	}

	if !scopes.ContainsScope(perms.Scopes, scopes.ScopeLogin) {
		response.HandleError(c, pufferpanel.ErrLoginNotPermitted, http.StatusForbidden)
		return
	}

	session, err := ss.CreateForUser(user)
	if response.HandleError(c, err, http.StatusInternalServerError) {
		return
	}

	data := &LoginResponse{}
	data.Scopes = perms.Scopes

	secure := false
	if c.Request.TLS != nil {
		secure = true
	}

	maxAge := int(time.Hour / time.Second)

	c.SetCookie("puffer_auth", session, maxAge, "/", "", secure, true)
	c.SetCookie("puffer_auth_expires", "", maxAge, "/", "", secure, false)

	c.JSON(http.StatusOK, data)
}

type LoginRequestData struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Scopes            []*scopes.Scope `json:"scopes,omitempty"`
	NeedsSecondFactor bool `json:"needsSecondFactor"`
}

type OtpRequestData struct {
	Token string `json:"token"`
}

type PasskeyLoginRequest struct {
	Email string `json:"email"`
}
