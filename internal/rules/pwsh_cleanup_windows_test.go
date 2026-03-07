//go:build windows

package rules

func cleanupSharedPwshWorker() {
	if sharedPwshHelper != nil {
		sharedPwshHelper.stop()
	}
}
