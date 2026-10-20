// altiward-forwarder-hook is SAP Privileges' post-change executable: it sends each change of
// admin rights straight from the Mac to Splunk, Sentinel or an HTTPS webhook. Settings come
// from the com.altiward.forwarder managed preferences; see docs/hook.md.
//
//	altiward-forwarder-hook <user> <admin|user> [reason]   (run by Privileges)
//	altiward-forwarder-hook --flush                        send queued events (the LaunchAgent)
//	altiward-forwarder-hook --test                         send one test event and print the result
//	altiward-forwarder-hook --version
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/Altiward/altiward-forwarder/internal/hook"
)

var version = "dev" // set with -ldflags "-X main.version=…"

func main() {
	env := hook.LiveEnv()
	env.Version = version
	if len(os.Args) == 2 {
		switch os.Args[1] {
		case "--version":
			fmt.Println(version)
			return
		case "--flush":
			os.Exit(hook.Flush(env))
		case "--test":
			os.Exit(hook.Test(env))
		}
	}
	// Privileges doesn't wait for the hook; finish within 5 seconds whatever happens, as the
	// Altiward agent's hook does. An event not sent by then is in the queue.
	time.AfterFunc(5*time.Second, func() { os.Exit(0) })
	os.Exit(hook.Run(os.Args[1:], env))
}
