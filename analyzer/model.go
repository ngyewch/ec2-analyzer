package analyzer

import (
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type SecurityGroupDescriptor struct {
	GroupId   string
	GroupName string
}

func toSecurityGroupDescriptor(securityGroup types.SecurityGroup) SecurityGroupDescriptor {
	return SecurityGroupDescriptor{
		GroupId:   *securityGroup.GroupId,
		GroupName: *securityGroup.GroupName,
	}
}

type PortDescriptor struct {
	DeclaredBy SecurityGroupDescriptor
	Source     SecurityGroupDescriptor
	IpProtocol string
	FromPort   *int32
	ToPort     *int32
}

func (descriptor PortDescriptor) String() string {
	var s string
	if descriptor.IpProtocol == "-1" {
		s += "All traffic"
	} else {
		s += descriptor.IpProtocol
	}
	s += "/"
	if (descriptor.FromPort == nil) || (descriptor.ToPort == nil) {
		s += "*"
	} else if *descriptor.FromPort != *descriptor.ToPort {
		s += fmt.Sprintf("%d-%d", *descriptor.FromPort, *descriptor.ToPort)
	} else {
		s += fmt.Sprintf("%d", *descriptor.FromPort)
	}
	s += fmt.Sprintf(" (%s)", descriptor.DeclaredBy.GroupName)
	return s
}

type TrafficDescriptor struct {
	IpProtocol string
	FromPort   *int32
	ToPort     *int32
}

func (descriptor TrafficDescriptor) String() string {
	var s string
	if descriptor.IpProtocol == "-1" {
		s += "All traffic"
	} else {
		s += descriptor.IpProtocol
	}
	s += "/"
	if (descriptor.FromPort == nil) || (descriptor.ToPort == nil) {
		s += "*"
	} else if *descriptor.FromPort != *descriptor.ToPort {
		s += fmt.Sprintf("%d-%d", *descriptor.FromPort, *descriptor.ToPort)
	} else {
		s += fmt.Sprintf("%d", *descriptor.FromPort)
	}
	return s
}

type Rule struct {
	Type              string
	DeclaredBy        SecurityGroupDescriptor
	TrafficDescriptor TrafficDescriptor
	Description       string
}

func toRule(ruleType string, securityGroupDescriptor SecurityGroupDescriptor, ipPermission types.IpPermission, userIdGroupPair types.UserIdGroupPair) Rule {
	var description string
	if userIdGroupPair.Description != nil {
		description = *userIdGroupPair.Description
	}
	return Rule{
		Type:       ruleType,
		DeclaredBy: securityGroupDescriptor,
		TrafficDescriptor: TrafficDescriptor{
			IpProtocol: *ipPermission.IpProtocol,
			FromPort:   ipPermission.FromPort,
			ToPort:     ipPermission.ToPort,
		},
		Description: description,
	}
}

func (rule Rule) String() string {
	return fmt.Sprintf("[%s] %s (%s)", rule.Type, rule.TrafficDescriptor, rule.DeclaredBy.GroupName)
}
