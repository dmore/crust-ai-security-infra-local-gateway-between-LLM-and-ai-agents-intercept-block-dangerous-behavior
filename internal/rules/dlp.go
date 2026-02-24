package rules

import "regexp"

// Hardcoded DLP (Data Loss Prevention) token detection patterns.
// Compiled at init, checked on all operations.
// Sourced from gitleaks v8.24, curated for blocking (not warning).

type dlpPattern struct {
	name    string
	re      *regexp.Regexp
	message string
}

var dlpPatterns = []dlpPattern{
	// AWS
	{
		name:    "builtin:dlp-aws-access-key",
		re:      regexp.MustCompile(`(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}`),
		message: "Cannot write AWS access key — potential credential leak",
	},

	// GitHub
	{
		name:    "builtin:dlp-github-token",
		re:      regexp.MustCompile(`(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}`),
		message: "Cannot write GitHub token — potential credential leak",
	},
	{
		name:    "builtin:dlp-github-fine-grained-token",
		re:      regexp.MustCompile(`github_pat_[A-Za-z0-9_]{82,}`),
		message: "Cannot write GitHub fine-grained token — potential credential leak",
	},

	// Slack
	{
		name:    "builtin:dlp-slack-token",
		re:      regexp.MustCompile(`xox[bpas]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{20,}`),
		message: "Cannot write Slack token — potential credential leak",
	},
	{
		name:    "builtin:dlp-slack-webhook",
		re:      regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{20,}`),
		message: "Cannot write Slack webhook URL — potential credential leak",
	},

	// Stripe
	{
		name:    "builtin:dlp-stripe-live-key",
		re:      regexp.MustCompile(`(?:sk|pk|rk)_live_[a-zA-Z0-9]{20,}`),
		message: "Cannot write Stripe live key — potential credential leak",
	},

	// Google
	{
		name:    "builtin:dlp-google-api-key",
		re:      regexp.MustCompile(`AIza[A-Za-z0-9_\-]{35}`),
		message: "Cannot write Google API key — potential credential leak",
	},

	// SendGrid
	{
		name:    "builtin:dlp-sendgrid-api-key",
		re:      regexp.MustCompile(`SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}`),
		message: "Cannot write SendGrid API key — potential credential leak",
	},

	// Heroku
	{
		name:    "builtin:dlp-heroku-api-key",
		re:      regexp.MustCompile(`heroku_[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`),
		message: "Cannot write Heroku API key — potential credential leak",
	},

	// GitLab
	{
		name:    "builtin:dlp-gitlab-pat",
		re:      regexp.MustCompile(`glpat-[A-Za-z0-9_\-]{20,}`),
		message: "Cannot write GitLab personal access token — potential credential leak",
	},

	// PyPI
	{
		name:    "builtin:dlp-pypi-token",
		re:      regexp.MustCompile(`pypi-[A-Za-z0-9_\-]{50,}`),
		message: "Cannot write PyPI token — potential credential leak",
	},

	// npm
	{
		name:    "builtin:dlp-npm-token",
		re:      regexp.MustCompile(`npm_[A-Za-z0-9]{36}`),
		message: "Cannot write npm token — potential credential leak",
	},

	// Shopify
	{
		name:    "builtin:dlp-shopify-shared-secret",
		re:      regexp.MustCompile(`shpss_[a-fA-F0-9]{32}`),
		message: "Cannot write Shopify shared secret — potential credential leak",
	},
	{
		name:    "builtin:dlp-shopify-access-token",
		re:      regexp.MustCompile(`shpat_[a-fA-F0-9]{32}`),
		message: "Cannot write Shopify access token — potential credential leak",
	},

	// Databricks
	{
		name:    "builtin:dlp-databricks-token",
		re:      regexp.MustCompile(`dapi[a-f0-9]{32}`),
		message: "Cannot write Databricks token — potential credential leak",
	},

	// Anthropic
	{
		name:    "builtin:dlp-anthropic-api-key",
		re:      regexp.MustCompile(`sk-ant-api03-[A-Za-z0-9_\-]{90,}`),
		message: "Cannot write Anthropic API key — potential credential leak",
	},

	// OpenAI
	{
		name:    "builtin:dlp-openai-project-key",
		re:      regexp.MustCompile(`sk-proj-[A-Za-z0-9_\-]{40,}`),
		message: "Cannot write OpenAI project key — potential credential leak",
	},

	// Stripe webhook signing secret
	{
		name:    "builtin:dlp-stripe-webhook-secret",
		re:      regexp.MustCompile(`whsec_[A-Za-z0-9]{20,}`),
		message: "Cannot write Stripe webhook secret — potential credential leak",
	},

	// age encryption
	{
		name:    "builtin:dlp-age-secret-key",
		re:      regexp.MustCompile(`AGE-SECRET-KEY-[A-Z0-9]{59}`),
		message: "Cannot write age secret key — potential credential leak",
	},

	// Add new patterns above this line.
}
