# AESite - App Engine site tools

This is `aesite`, a package of tools for creating websites and apps in Go using Google App Engine.

It includes functions and types that help with managing users, sessions, and settings, among other things.

The following sections give an overview of this package’s features.
For full documentation, see https://godoc.org/github.com/bobg/aesite.

## Datastore emulator

The function `DSTest` starts an instance of the Google Cloud Datastore emulator.
It adds the necessary settings to the process’s environment variables
so that `datastore.NewClient` will connect to the local emulator,
not the cloud service.

## Users

This package includes a `User` type that is backed by Google Cloud
Datastore entities
having [kind](https://cloud.google.com/datastore/docs/concepts/entities) `User`.
Users are keyed on e-mail addresses, which must be unique per user.
This package manages that e-mail address,
an “address-verified” flag,
and password info.
Applications may associate additional data with a user
(that this package will faithfully store and retrieve)
by defining their own types implementing the `UserWrapper` interface.

## Sessions

This package includes a `Session` type that is backed by Google Cloud
Datastore entities having
[kind](https://cloud.google.com/datastore/docs/concepts/entities)
`Session`. A `Session` is created when a user logs in.

The package defines an HTTP cookie (named `s`) for storing a session key.
An HTTP request handler can use the cookie to retrieve the `Session`
and then the associated `User`.

