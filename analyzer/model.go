package analyzer

import (
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"strings"
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

type InstanceDescriptor struct {
	InstanceId   string
	InstanceName string
}

func toInstanceDescriptor(instance types.Instance) InstanceDescriptor {
	return InstanceDescriptor{
		InstanceId:   *instance.InstanceId,
		InstanceName: getTagByName(instance.Tags, "Name"),
	}
}

type PortDescriptor struct {
	DeclaredBy SecurityGroupDescriptor
	Source     SecurityGroupDescriptor
	IpProtocol string
	FromPort   *int32
	ToPort     *int32
}

func toPortDescriptor(declaringSecurityGroup types.SecurityGroup, sourceSecurityGroup types.SecurityGroup, ipPermission types.IpPermission) PortDescriptor {
	return PortDescriptor{
		DeclaredBy: toSecurityGroupDescriptor(declaringSecurityGroup),
		Source:     toSecurityGroupDescriptor(sourceSecurityGroup),
		IpProtocol: *ipPermission.IpProtocol,
		FromPort:   ipPermission.FromPort,
		ToPort:     ipPermission.ToPort,
	}
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

type PortDescriptors []PortDescriptor

func (descriptors PortDescriptors) String() string {
	var parts []string
	for _, descriptor := range descriptors {
		parts = append(parts, descriptor.String())
	}
	return strings.Join(parts, ", ")
}
