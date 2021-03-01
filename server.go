package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/gorilla/mux"
)

// move to own file and group with other requests
type LoginRequest struct {
	Username string `json:"username" validate:"required,email"`
	Password string `json:"password" validate:"required"`
	Token    string `json:"token" validate:"required,min=4,max=4"`
}

// move to own file and group with other request handlers
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	// should do this for every request and not repeat for every handler
	w.Header().Add("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Allow-Origin", "*") // * should be a secret and set to the request origin for the actual servers outside of develop
	if r.Method == http.MethodOptions {
		return
	}

	var loginRequest LoginRequest

	err := json.NewDecoder(r.Body).Decode(&loginRequest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// validate request, would probably put this in middleware
	validator := validator.New()
	err = validator.Struct(loginRequest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = Authorize(loginRequest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
	}
}

// Authorize takes a loginRequest and validates the user name, password and token. the user name and password should be stored in a database.
// the password should be hashed in said database.
func Authorize(loginRequest LoginRequest) error {

	err := ValidateToken(loginRequest.Token)
	if err != nil {
		return err
	}

	// password should be encrypted, and stored in a database.
	if loginRequest.Username != "c137@onecause.com" || loginRequest.Password != "#th@nH@rm#y#r!$100%D0p#" {
		return fmt.Errorf("Invalid credentials")
	}

	return nil
}

// ValidateToken takes a 4 char string of format HHMM, splits the string and validates the hour and minutes to ensure they're a valid hour and minute.
// generally a token would be a JWT, passed as a Bearer token and validated in middleware.
func ValidateToken(token string) error {

	hour := token[0:2]
	iHour, err := strconv.Atoi(hour)
	if err != nil {
		return err
	}

	if iHour > 24 || iHour < 0 {
		return fmt.Errorf(("Invalid token hour"))
	}

	min := token[2:4]
	iMinute, err := strconv.Atoi(min)
	if err != nil {
		return err
	}

	if iMinute > 60 || iMinute < 0 {
		return fmt.Errorf("Invalid token minute")
	}

	return nil
}

func main() {
	var wait time.Duration
	r := mux.NewRouter()
	// didn't explicity say method options allowed in sepc, i could have turned this off in angular if i thought it was an omission on purpose.
	r.HandleFunc("/login", LoginHandler).Methods(http.MethodPost, http.MethodOptions)
	r.Use(mux.CORSMethodMiddleware(r))

	srv := &http.Server{
		Addr:         "0.0.0.0:5000",
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      r,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Println(err)
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	<-c

	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()

	srv.Shutdown(ctx)
	log.Println("shutting down")
	os.Exit(0)
}
