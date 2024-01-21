/*
 Copyright 2020 Padduck, LLC
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  	http://www.apache.org/licenses/LICENSE-2.0
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

package auth

import (
	"encoding/json"
	"errors"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/pufferpanel/pufferpanel/v2"
	"github.com/pufferpanel/pufferpanel/v2/config"
	"github.com/pufferpanel/pufferpanel/v2/middleware"
	"github.com/pufferpanel/pufferpanel/v2/response"
	"github.com/pufferpanel/pufferpanel/v2/services"
	"net/http"
	"time"
)

func LoginPost(c *gin.Context) {
	db := middleware.GetDatabase(c)
	us := &services.User{DB: db}
	ps := &services.Permission{DB: db}

	httpRequest, err := http.NewRequest("GET", config.CloudflareGetIdentity.Value(), nil)
	if response.HandleError(c, err, http.StatusInternalServerError) {
		return
	}

	httpRequest.AddCookie(&http.Cookie{
		Name:  "CF_Authorization",
		Value: c.GetHeader("CF_Authorization"),
	})

	httpResponse, err := http.DefaultClient.Do(httpRequest)
	if response.HandleError(c, err, http.StatusInternalServerError) {
		return
	}

	if httpResponse.StatusCode != http.StatusOK {
		response.HandleError(c, errors.New("invalid cloudflare response"), http.StatusUnauthorized)
		return
	}

	var identity CloudflareIdentity
	err = json.NewDecoder(httpResponse.Body).Decode(&identity)
	if response.HandleError(c, err, http.StatusInternalServerError) {
		return
	}

	user, err := us.GetByEmail(identity.Email)
	if response.HandleError(c, err, http.StatusUnauthorized) {
		return
	}

	session, err := services.GenerateSession(user.ID)
	if response.HandleError(c, err, http.StatusInternalServerError) {
		return
	}

	perms, err := ps.GetForUserAndServer(user.ID, nil)
	if response.HandleError(c, err, http.StatusInternalServerError) {
		return
	}

	data := &LoginResponse{}
	data.Session = session
	data.Scopes = perms.ToScopes()

	secure := false
	if c.Request.TLS != nil {
		secure = true
	}
	//TODO: Change to httponly=true when UI is able to use it properly
	c.SetCookie("puffer_auth", session, int(time.Hour/time.Second), "/", "", secure, false)

	c.JSON(http.StatusOK, data)
}

func OtpPost(c *gin.Context) {
	db := middleware.GetDatabase(c)
	us := &services.User{DB: db}
	ps := &services.Permission{DB: db}

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
		userSession.Save()
		response.HandleError(c, pufferpanel.ErrSessionExpired, http.StatusBadRequest)
		return
	}

	user, session, err := us.LoginOtp(email, request.Token)
	if response.HandleError(c, err, http.StatusBadRequest) {
		return
	}

	perms, err := ps.GetForUserAndServer(user.ID, nil)
	if response.HandleError(c, err, http.StatusInternalServerError) {
		return
	}

	data := &LoginResponse{}
	data.Session = session
	data.Scopes = perms.ToScopes()

	secure := false
	if c.Request.TLS != nil {
		secure = true
	}
	//TODO: Change to httponly=true when UI is able to use it properly
	c.SetCookie("puffer_auth", session, int(time.Hour/time.Second), "/", "", secure, false)

	c.JSON(http.StatusOK, data)
}

type CloudflareIdentity struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type LoginOtpResponse struct {
	OtpNeeded bool `json:"otpNeeded"`
}

type LoginResponse struct {
	Session string              `json:"session"`
	Scopes  []pufferpanel.Scope `json:"scopes,omitempty"`
}

type OtpRequestData struct {
	Token string `json:"token"`
}
