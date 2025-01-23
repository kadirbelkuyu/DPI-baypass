package proxy

import (
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

func ConfigureSystemProxy(enable bool, addr string, port int) error {
	switch runtime.GOOS {
	case "darwin":
		return configureMacOSProxy(enable, addr, port)
	case "linux":
		return configureLinuxProxy(enable, addr, port)
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

func configureMacOSProxy(enable bool, addr string, port int) error {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return err
	}

	services := []string{}
	for _, service := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(service, "*") && service != "" {
			services = append(services, service)
		}
	}

	for _, network := range services {
		if enable {
			err = exec.Command("networksetup", "-setwebproxy", network, addr, strconv.Itoa(port)).Run()
			if err == nil {
				err = exec.Command("networksetup", "-setsecurewebproxy", network, addr, strconv.Itoa(port)).Run()
			}
		} else {
			err = exec.Command("networksetup", "-setwebproxystate", network, "off").Run()
			if err == nil {
				err = exec.Command("networksetup", "-setsecurewebproxystate", network, "off").Run()
			}
		}
		if err == nil {
			break
		}
	}
	return err
}

func configureLinuxProxy(enable bool, addr string, port int) error {

	return nil
}

