package rules

import "regexp"

// compile-time validation: all DLP patterns must compile.
var _ = func() int {
	for _, p := range dlpPatterns {
		_ = regexp.MustCompile(p.re.String())
	}
	return 0
}()
