/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package middleware

import (
	"intel/isecl/authservice/config"
	"intel/isecl/authservice/context"
	"intel/isecl/authservice/defender"
	_ "intel/isecl/authservice/defender"
	"intel/isecl/authservice/repository"
	"intel/isecl/authservice/types"
	"net/http"
	"time"
	_ "time"

	_ "github.com/gorilla/context"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

var defend *defender.Defender

func init() {
	c := config.Global()

	defend = defender.New(c.AuthDefender.MaxAttempts,
		time.Duration(c.AuthDefender.IntervalMins)*time.Minute,
		time.Duration(c.AuthDefender.LockoutDurationMins)*time.Minute)
	quit := make(chan struct{})

	go defend.CleanupTask(quit)

}

func NewBasicAuth(u repository.UserRepository) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// TODO : switch to username only
			username, password, ok := r.BasicAuth()

			if !ok {
				log.Info("No Basic Auth provided")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			//todo:remove this entry that is used for debug
			log.Trace("Attempting to authenticate user: ", username)
			// first let us make sure that this is not a user that is banned

			foundInDefendList := false
			// check if we have an entry for the client in the defend map.
			// There are several scenarios in this case
			if client, ok := defend.Client(username); ok {
				//fmt.Println("Found user in defend list: ", username)
				foundInDefendList = true
				if client.Banned() {
					//fmt.Println("User was banned - but ban might have expired - need to check")
					// case 1. Client is banned - however, the ban expired but cleanup is not done.
					// just delete the flient from the map
					if client.BanExpired() {
						//fmt.Println("user ban has expired. should remove client")
						defend.RemoveClient(client.Key())
					} else {
						log.Errorf("Maximum login attempts exceeded for user : %s. Banned !", username)
						w.WriteHeader(http.StatusTooManyRequests)
						return
					}
				}
			}

			// fetch by user
			user, err := u.Retrieve(types.User{Name: username})
			if err != nil {
				log.WithError(err).Errorf("BasicAuth failure: could not retrieve user: %s", username)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if err := user.CheckPassword([]byte(password)); err != nil {
				log.WithError(err).Error("BasicAuth failure: password mismatch, user: ", username)
				if defend.Inc(username) {
					log.Errorf("Maximum login attempts exceeded for user : %s. Banned !", username)
					w.WriteHeader(http.StatusTooManyRequests)
					return
				}
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			// If we found the user earlier in the defend list, we should now remove as user is authorized
			if foundInDefendList {
				//fmt.Println("Previously had entry in defender list. Need to remove now")
				if client, ok := defend.Client(username); ok {
					//fmt.Println("About to remove user from defender list as password successful")
					defend.RemoveClient(client.Key())
				}
			}

			roles, err := u.GetRoles(types.User{Name: username})
			if err != nil {
				log.WithError(err).Error("Database error: unable to retrive roles")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			r = context.SetUserRoles(r, roles)
			next.ServeHTTP(w, r)
		})
	}
}
