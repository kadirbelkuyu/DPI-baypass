package proxy

import (
	"fmt"
	"os/exec"
)

func ConfigureMacProxy(enable bool, addr string, port int) error {
	action := "off"
	if enable {
		cmd := exec.Command("networksetup", "-setwebproxy", "Wi-Fi", addr, fmt.Sprintf("%d", port))
		if err := cmd.Run(); err != nil {
			return err
		}
		cmd = exec.Command("networksetup", "-setsecurewebproxy", "Wi-Fi", addr, fmt.Sprintf("%d", port))
		if err := cmd.Run(); err != nil {
			return err
		}
		action = "on"
	}

	cmd := exec.Command("networksetup", "-setwebproxystate", "Wi-Fi", action)
	if !enable {
		cmd = exec.Command("networksetup", "-setdnsservers", "Wi-Fi", "empty")
	}
	return cmd.Run()
}

func ConfigureLinuxProxy(enable bool, addr string, port int) error {
	if enable {
		cmd := exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", "manual")
		if err := cmd.Run(); err != nil {
			return err
		}
		cmd = exec.Command("gsettings", "set", "org.gnome.system.proxy.http", "host", addr)
		cmd.Run()
		cmd = exec.Command("gsettings", "set", "org.gnome.system.proxy.http", "port", fmt.Sprintf("%d", port))
		cmd.Run()
		cmd = exec.Command("gsettings", "set", "org.gnome.system.proxy.https", "host", addr)
		cmd.Run()
		cmd = exec.Command("gsettings", "set", "org.gnome.system.proxy.https", "port", fmt.Sprintf("%d", port))
		return cmd.Run()
	}
	cmd := exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", "none")
	return cmd.Run()
}
