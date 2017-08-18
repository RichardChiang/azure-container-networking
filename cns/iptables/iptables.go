// Copyright 2017 Microsoft. All rights reserved.
// MIT License

package iptables

import (
	"fmt"
	"io/ioutil"
	"os/exec"
	"strings"

	"github.com/Azure/azure-container-networking/cns"
	"github.com/Azure/azure-container-networking/log"
)

// iptableClient specifies a client to connect to iptables.
type IpTableClient struct {
}

// NewIpTableClient creates a new ip table client.
func NewIpTableClient() (*IpTableClient, error) {
	return &IpTableClient{}, nil
}

// installIPTables installs the iptables package
func (ipt *IpTableClient) InstallIPTables() {
	version, _ := ioutil.ReadFile("/proc/version")
	os := strings.ToLower(string(version))

	if strings.Contains(os, "ubuntu") {
		executeShellCommand("apt-get install iptables")
	} else if strings.Contains(os, "redhat") {
		executeShellCommand("yum install iptables")
	} else {
		log.Printf("Unable to detect OS platform. Please make sure the iptables package is installed.")
	}
}

// enableIPForwarding enables IPV4 forwarding.
func (ipt *IpTableClient) EnableIPForwarding() error {
	err := executeShellCommand("sysctl net.ipv4.ip_forward=1")
	if err != nil {
		err = executeShellCommand("echo '1' < /proc/sys/net/ipv4/ip_forward")
	}
	return err
}

// enableMasquerade enables ip masquerading for NAT
func (ipt *IpTableClient) EnableMasquerade() error {
	return nil
	//return executeShellCommand("iptables -t nat -A POSTROUTING -j MASQUERADE")
}

// Wrapper for executing shell command
func executeShellCommand(command string) error {
	log.Debugf("[iptables] %s", command)
	cmd := exec.Command("sh", "-c", command)
	err := cmd.Start()
	if err != nil {
		return err
	}
	return cmd.Wait()
}

// addPreroutingFilter adds a filter to the prerouting chain
func (ipt *IpTableClient) AddPreroutingFilters(loadBalancerConfig cns.LBConfiguration) error {
	sourceIP := loadBalancerConfig.SourceIP
	sourcePort := loadBalancerConfig.SourcePort
	destinationIPs := loadBalancerConfig.DestinationConfig.IPAddresses
	destinationPort := loadBalancerConfig.DestinationConfig.Port
	numIps := len(destinationIPs)
	var err error

	for i := 0; i < numIps; i++ {
		probability := 1 / float64(numIps-i)

		command := fmt.Sprintf(
			"iptables -t nat -A PREROUTING -p tcp -d %s --dport %s -m state --state NEW -m statistic --mode random --probability %f -j DNAT --to-destination %s:%s",
			sourceIP, sourcePort, probability, destinationIPs[i], destinationPort)
		err := executeShellCommand(command)

		if err != nil {
			log.Printf("Error adding prerouting filter on DNAT.")
			return err
		}

		command = fmt.Sprintf(
			"iptables -t nat -A OUTPUT -p tcp -d %s --dport %s -m state --state NEW -m statistic --mode random --probability %f -j DNAT --to-destination %s:%s",
			sourceIP, sourcePort, probability, destinationIPs[i], destinationPort)
		err = executeShellCommand(command)
		log.Printf("Added a filter %v", command)

		if err != nil {
			log.Printf("Error adding output filter on DNAT.")
			return err
		}
	}
	log.Printf("Finished adding filter rules to Load Balancer.")
	return err
}

// DeletePreroutingFilters removes filters in the prerouting chain
func (ipt *IpTableClient) DeletePreroutingFilters(loadBalancerConfig cns.LBConfiguration) error {
	sourceIP := loadBalancerConfig.SourceIP
	sourcePort := loadBalancerConfig.SourcePort
	destinationIPs := loadBalancerConfig.DestinationConfig.IPAddresses
	destinationPort := loadBalancerConfig.DestinationConfig.Port
	numIps := len(destinationIPs)
	var err error

	for i := 0; i < numIps; i++ {
		probability := 1 / float64(numIps-i)

		command := fmt.Sprintf(
			"iptables -t nat -D PREROUTING -p tcp -d %s --dport %s -m state --state NEW -m statistic --mode random --probability %f -j DNAT --to-destination %s:%s",
			sourceIP, sourcePort, probability, destinationIPs[i], destinationPort)
		err := executeShellCommand(command)

		if err != nil {
			log.Printf("Error adding prerouting filter on DNAT.")
			return err
		}

		command = fmt.Sprintf(
			"iptables -t nat -D OUTPUT -p tcp -d %s --dport %s -m state --state NEW -m statistic --mode random --probability %f -j DNAT --to-destination %s:%s",
			sourceIP, sourcePort, probability, destinationIPs[i], destinationPort)
		err = executeShellCommand(command)

		if err != nil {
			log.Printf("Error deleting output filter on DNAT.")
			return err
		}
	}
	log.Printf("Finished deleting filter rules to Load Balancer.")
	return err
}
