package handler

import (
	"fmt"
	"github.com/analogj/scrutiny/webapp/backend/pkg"
	"github.com/analogj/scrutiny/webapp/backend/pkg/config"
	"github.com/analogj/scrutiny/webapp/backend/pkg/database"
	"github.com/analogj/scrutiny/webapp/backend/pkg/models/collector"
	"github.com/analogj/scrutiny/webapp/backend/pkg/notify"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/sirupsen/logrus"
	"net/http"
	"os"
)

func UploadDeviceMetrics(c *gin.Context) {
	//db := c.MustGet("DB").(*gorm.DB)
	logger := c.MustGet("LOGGER").(*logrus.Entry)
	appConfig := c.MustGet("CONFIG").(config.Interface)
	//influxWriteDb := c.MustGet("INFLUXDB_WRITE").(*api.WriteAPIBlocking)
	deviceRepo := c.MustGet("DEVICE_REPOSITORY").(database.DeviceRepo)

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
				logger.Errorln("An error occurred while updating device data from smartctl metrics:", err)
				c.JSON(http.StatusInternalServerError, gin.H{"success": false})
				return
			}

			if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
				check_uid := fmt.Sprint(claims["userdata"].(map[string]interface{})["uid"])
				if !contains(nc_uids, check_uid) {
					logger.Errorln("An unauthorized user was caught while updating device data from smartctl metrics")
					c.JSON(http.StatusInternalServerError, gin.H{"success": false})
					return
				}
			} else {
				logger.Errorln("An error occurred while updating device data from smartctl metrics:", err)
				c.JSON(http.StatusInternalServerError, gin.H{"success": false})
				return
			}
		} else {	
			logger.Errorln("An error occurred while updating device data from smartctl metrics: no jwt")
			c.JSON(http.StatusInternalServerError, gin.H{"success": false})
			return
		}
	}

	//appConfig := c.MustGet("CONFIG").(config.Interface)

	if c.Param("wwn") == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false})
	}

	var collectorSmartData collector.SmartInfo
	err := c.BindJSON(&collectorSmartData)
	if err != nil {
		logger.Errorln("Cannot parse SMART data", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false})
		return
	}

	//update the device information if necessary
	updatedDevice, err := deviceRepo.UpdateDevice(c, c.Param("wwn"), collectorSmartData)
	if err != nil {
		logger.Errorln("An error occurred while updating device data from smartctl metrics:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false})
		return
	}

	// insert smart info
	smartData, err := deviceRepo.SaveSmartAttributes(c, c.Param("wwn"), collectorSmartData)
	if err != nil {
		logger.Errorln("An error occurred while saving smartctl metrics", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false})
		return
	}

	if smartData.Status != pkg.DeviceStatusPassed {
		//there is a failure detected by Scrutiny, update the device status on the homepage.
		updatedDevice, err = deviceRepo.UpdateDeviceStatus(c, c.Param("wwn"), smartData.Status)
		if err != nil {
			logger.Errorln("An error occurred while updating device status", err)
			c.JSON(http.StatusInternalServerError, gin.H{"success": false})
			return
		}
	}

	// save smart temperature data (ignore failures)
	err = deviceRepo.SaveSmartTemperature(c, c.Param("wwn"), updatedDevice.DeviceProtocol, collectorSmartData)
	if err != nil {
		logger.Errorln("An error occurred while saving smartctl temp data", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false})
		return
	}

	//check for error
	if notify.ShouldNotify(
		updatedDevice,
		smartData,
		pkg.MetricsStatusThreshold(appConfig.GetInt(fmt.Sprintf("%s.metrics.status_threshold", config.DB_USER_SETTINGS_SUBKEY))),
		pkg.MetricsStatusFilterAttributes(appConfig.GetInt(fmt.Sprintf("%s.metrics.status_filter_attributes", config.DB_USER_SETTINGS_SUBKEY))),
	) {
		//send notifications

		liveNotify := notify.New(
			logger,
			appConfig,
			updatedDevice,
			false,
		)
		_ = liveNotify.Send() //we ignore error message when sending notifications.
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}
