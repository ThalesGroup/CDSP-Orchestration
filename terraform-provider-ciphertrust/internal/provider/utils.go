package provider

import (
	"fmt"
	"strings"
	"time"
)

func trimString(data string) string {
	cleaned := strings.Trim(data, "\"")
	return cleaned
}

// logEntryExit is a function that wraps another function to log its entry and exit.
func logEntryExit(f func() error) func() error {
	return func() error {
		start := time.Now()
		defer func() {
			fmt.Printf("Function executed in %v\n", time.Since(start))
		}()
		fmt.Println("Entering function...")
		err := f()
		fmt.Println("Exiting function...")
		return err
	}
}
