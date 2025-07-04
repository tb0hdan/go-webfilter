package firewall

type Firewall interface {
	InstallRules(redirectPort int) error
	UninstallRules() error
}
