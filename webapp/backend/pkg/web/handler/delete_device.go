package handler

import (
	"fmt"
	"github.com/analogj/scrutiny/webapp/backend/pkg/config"
	"github.com/analogj/scrutiny/webapp/backend/pkg/database"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/sirupsen/logrus"
	"net/http"
	"os"
)

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func DeleteDevice(c *gin.Context) {
	logger := c.MustGet("LOGGER").(*logrus.Entry)
	deviceRepo := c.MustGet("DEVICE_REPOSITORY").(database.DeviceRepo)
	appConfig := c.MustGet("CONFIG").(config.Interface)
	nc_uids := appConfig.GetStringSlice("nextcloud.uids")

	if len(nc_uids) != 0 {
		jwt_string, jwt_present := c.GetQuery("jwt")
		if jwt_present {
			token, err := jwt.Parse(jwt_string, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
					return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
				}

				jwt_secret_path := appConfig.GetString("nextcloud.jwt_secret")

				if jwt_secret_path == "" {
					return nil, fmt.Errorf("nextcloud.jwt_secret not present")
				}

				jwt_secret, err := os.ReadFile(jwt_secret_path)

				if err != nil {
					return nil, err
				}

				return jwt.ParseECPublicKeyFromPEM(jwt_secret)
			})

			if err != nil {
				logger.Errorln("An error occurred while deleting device", err)
				c.JSON(http.StatusInternalServerError, gin.H{"success": false})
				return
			}

			if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
				check_uid := fmt.Sprint(claims["userdata"].(map[string]interface{})["uid"])
				if !contains(nc_uids, check_uid) {
					logger.Errorln("An unauthorized user was caught while deleting device")
					c.JSON(http.StatusInternalServerError, gin.H{"success": false})
					return
				}
			} else {
				logger.Errorln("An error occurred while deleting device", err)
				c.JSON(http.StatusInternalServerError, gin.H{"success": false})
				return
			}
		}
	}

	err := deviceRepo.DeleteDevice(c, c.Param("wwn"))
	if err != nil {
		logger.Errorln("An error occurred while deleting device", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}
