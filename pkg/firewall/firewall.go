package firewall

type Firewall interface {
	InstallRules(redirectPort int, redirectHTTPSPort int) error
	UninstallRules() error
}
