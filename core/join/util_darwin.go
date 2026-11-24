package main

import "os/exec"

// sudoExplained records that explainSudo already spoke this run.
var sudoExplained bool

// explainSudo says once, before the OS asks, why a password is needed, so a
// bare "Password:" never appears unexplained. Silent when no prompt will come.
// It uses the same trusted sudo as run, never a PATH lookup.
func explainSudo(why string) {
	if sudoExplained || isRoot() {
		return
	}
	sudo := sudoPath()
	if sudo == "" {
		return
	}
	if exec.Command(sudo, "-n", "true").Run() == nil {
		return // sudo won't ask: already authorized
	}
	sudoExplained = true
	note("Your computer's password is needed %s. It goes to the system, not to Hogman.", why)
}
