# Microsoft Firebase Custom IDP

This repository contains a Go application which shows different authentication ways using Microsoft / Firebase (Using Azure EntraID and Firebase Authentication)

## Requirements

- Go 1.21.5

Please ensure that you have the correct version of Go installed on your system before running this application. You can check your Go version by running the following command in your terminal:

```sh
go version
```

If you do not have Go installed or have a different version, you can download Go 1.21.5 from the [official Go website](https://golang.org/dl/).

## Project Structure

- [``cmd/main.go``]: The entry point of the application.
- [``config/config.go``]: Contains the configuration for the application.
- [``internal/handlers/handlers.go``]: Contains the HTTP handlers for the application.
- [``models/user.go``]: Defines the User model.
- [``services/db.go``]: Contains the database initialization logic.

## How to Run

You can run the application using the provided Makefile:

```sh
make run
```

This will start the server on port 8080.

## Environment Variables

The application uses environment variables for configuration. You can find an example in the [``.env.example``] file.

## Dependencies

The application uses several dependencies, which are listed in the [``go.mod``] files.
