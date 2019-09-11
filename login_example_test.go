package aesite_test

import (
	"net/http"

	"cloud.google.com/go/datastore"

	"github.com/bobg/aesite"
)

func ExampleSession() {
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/logout", handleLogout)

	http.ListenAndServe(":8080", nil)
}

func handleLogin(w http.ResponseWriter, req *http.Request) {
	var (
		ctx      = req.Context()
		email    = req.FormValue("email")
		password = req.FormValue("password")
	)

	client, err := datastore.NewClient(ctx, xxx)

	var user aesite.User // or your own user type implementing UserWrapper
	err := aesite.LookupUser(ctx, client, email, &user)
	if err != nil {
		http.Error(w, "xxx", http.StatusXXX)
		return
	}

	if !user.CheckPW(password) {
		http.Error(w, "invalid email/password pair", http.StatusUnauthorized)
		return
	}

	// Create a new login session.
	sess, err := aesite.NewSession(ctx, client, user.Key())
	if err != nil {
		// xxx
	}

	csrf, err := sess.CSRFToken()
	if err != nil {
		// xxx
	}

	sess.SetCookie(w)

	// xxx render page
}

func handleLogout(w http.ResponseWriter, req *http.Request) {
	var (
		ctx  = req.Context()
		csrf = req.FormValue("csrf")
	)

	sess, err := aesite.GetSession(ctx, client, req)
	if err != nil {
		// xxx
	}
	if sess == nil {
		// xxx
	}

	err = sess.CSRFCheck(csrf)
	if err != nil {
		// xxx
	}

	err = sess.Cancel(ctx, client)
	if err != nil {
		// xxx
	}

	// xxx respond
}
