package main

import (
	"os"
)

func main() {
	app := &App{}

	err := app.Run(os.Args)
	if err != nil {
		os.Exit(1)
	}
}
