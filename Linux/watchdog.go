package main

import (
    "fmt"
    "os/exec"
    "time"
)

func main() {
    for {
        // Check if the process is running
        if !isProcessRunning("/sbin/bash") {
            // If not, start it
            startProcess("/sbin/bash", "")
        }
        // Wait for a minute before checking again
        time.Sleep(time.Minute)
    }
}

func isProcessRunning(processName string) bool {
    // Check if the process is running by running a command
    cmd := exec.Command("pgrep", "-x", processName)
    err := cmd.Run()
    return err == nil
}

func startProcess(processPath string, processArgs string) {
    // Start the process by running a command
    cmd := exec.Command(processPath, processArgs)
    err := cmd.Start()
    if err != nil {
        fmt.Println("Error starting process:", err)
    }
}