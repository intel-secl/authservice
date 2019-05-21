package resource

import (
	"encoding/json"
	"intel/isecl/authservice/config"
	"intel/isecl/authservice/constants"
	"intel/isecl/authservice/context"
	"intel/isecl/authservice/repository"
	"intel/isecl/authservice/types"
	"net/http"
	"time"

	"github.com/gorilla/handlers"
	log "github.com/sirupsen/logrus"

	"github.com/gorilla/mux"
)

func SetHeartbeat(r *mux.Router, db repository.AASDatabase) {
	r.Handle("/heartbeat", handlers.ContentTypeHandler(hostHeartbeatHandler(db), "application/json")).Methods("POST")
}

func hostHeartbeatHandler(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		var hb types.HostHeartbeat
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err := dec.Decode(&hb)
		if err != nil {
			return err
		}
		// Check query authority
		roles := context.GetUserRoles(r)
		actionAllowed := false
		for _, role := range roles {
			if role.Name == constants.HostSelfUpdateGroupName && role.Domain == hb.ID {
				actionAllowed = true
				break
			}
		}
		if !actionAllowed {
			return &privilegeError{Message: "privilege error: heartbest",
				StatusCode: http.StatusForbidden}
		}
		// Update DB
		var updatedHost *types.Host
		if updatedHost, err = db.HostRepository().Retrieve(types.Host{ID: hb.ID}); err != nil {
			return err
		}
		updatedHost.UpdatedAt = time.Now()
		if err = db.HostRepository().Update(*updatedHost); err != nil {
			return err
		}
		log.WithField("heartbeat", hb).Trace("received heartbeat")

		w.Header().Set("Content-Type", "application/json")
		c := config.Global()
		respBody := types.HostHeartbeat{IntervalMins: c.HeartbeatIntervalMins}
		err = json.NewEncoder(w).Encode(&respBody)
		if err != nil {
			return err
		}
		return nil
	}
}
