package analyzer

import (
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"slices"
)

type SecurityGroupReportEntry struct {
	SecurityGroup   types.SecurityGroup
	Descriptor      SecurityGroupDescriptor
	UsedBy          []Instance
	ReferencedBy    []Rule
	ReferenceErrors []SecurityGroupDescriptor
}

func (entry *SecurityGroupReportEntry) AddUsedBy(instance Instance) {
	if !slices.Contains(entry.UsedBy, instance) {
		entry.UsedBy = append(entry.UsedBy, instance)
	}
}

func (entry *SecurityGroupReportEntry) AddReferencedBy(rule Rule) {
	if !slices.Contains(entry.ReferencedBy, rule) {
		entry.ReferencedBy = append(entry.ReferencedBy, rule)
	}
}

func (entry *SecurityGroupReportEntry) AddReferenceError(securityGroupDescriptor SecurityGroupDescriptor) {
	if !slices.Contains(entry.ReferenceErrors, securityGroupDescriptor) {
		entry.ReferenceErrors = append(entry.ReferenceErrors, securityGroupDescriptor)
	}
}
