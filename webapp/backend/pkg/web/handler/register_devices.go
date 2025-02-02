package handler

import (
	"fmt"
	"github.com/analogj/scrutiny/webapp/backend/pkg/config"
	"github.com/analogj/scrutiny/webapp/backend/pkg/database"
	"github.com/analogj/scrutiny/webapp/backend/pkg/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"net/http"
	"os"
)

// register devices that are detected by various collectors.
// This function is run everytime a collector is about to start a run. It can be used to update device metadata.
func RegisterDevices(c *gin.Context) {
	deviceRepo := c.MustGet("DEVICE_REPOSITORY").(database.DeviceRepo)
	logger := c.MustGet("LOGGER").(*logrus.Entry)
	appConfig := c.MustGet("CONFIG").(config.Interface)
	nc_uids := appConfig.GetStringSlice("nextcloud.uids")

	if c.ClientIP() != "127.0.0.1" && len(nc_uids) != 0 {
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
				logger.Errorln("An error occurred while registering devices", err)
				c.JSON(http.StatusInternalServerError, gin.H{"success": false})
				return
			}

			if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
				check_uid := fmt.Sprint(claims["userdata"].(map[string]interface{})["uid"])
				if !contains(nc_uids, check_uid) {
					logger.Errorln("An unauthorized user was caught while registering device")
					c.JSON(http.StatusInternalServerError, gin.H{"success": false})
					return
				}
			} else {
				logger.Errorln("An error occurred while registering devices", err)
				c.JSON(http.StatusInternalServerError, gin.H{"success": false})
				return
			}
		} else {
			logger.Errorln("An error occurred while registering devices <no jwt>")
			c.JSON(http.StatusInternalServerError, gin.H{"success": false})
			return
		}
	}

	var collectorDeviceWrapper models.DeviceWrapper
	err := c.BindJSON(&collectorDeviceWrapper)
	if err != nil {
		logger.Errorln("Cannot parse detected devices", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false})
		return
	}

	//filter any device with empty wwn (they are invalid)
	detectedStorageDevices := lo.Filter[models.Device](collectorDeviceWrapper.Data, func(dev models.Device, _ int) bool {
		return len(dev.WWN) > 0
	})

	errs := []error{}
	for _, dev := range detectedStorageDevices {
		//insert devices into DB (and update specified columns if device is already registered)
		// update device fields that may change: (DeviceType, HostID)
		if err := deviceRepo.RegisterDevice(c, dev); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		logger.Errorln("An error occurred while registering devices", errs)
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
		})
		return
	} else {
		c.JSON(http.StatusOK, models.DeviceWrapper{
			Success: true,
			Data:    detectedStorageDevices,
		})
		return
	}
}
