package analyzer

import "slices"

type SecurityGroupReportEntry struct {
	Descriptor      SecurityGroupDescriptor
	UsedBy          []Instance
	ReferencedBy    []PortDescriptor
	ReferenceErrors []SecurityGroupDescriptor
}

func (entry *SecurityGroupReportEntry) AddUsedBy(instance Instance) {
	if !slices.Contains(entry.UsedBy, instance) {
		entry.UsedBy = append(entry.UsedBy, instance)
	}
}

func (entry *SecurityGroupReportEntry) AddReferencedBy(portDescriptor PortDescriptor) {
	if !slices.Contains(entry.ReferencedBy, portDescriptor) {
		entry.ReferencedBy = append(entry.ReferencedBy, portDescriptor)
	}
}

func (entry *SecurityGroupReportEntry) AddReferenceError(securityGroupDescriptor SecurityGroupDescriptor) {
	if !slices.Contains(entry.ReferenceErrors, securityGroupDescriptor) {
		entry.ReferenceErrors = append(entry.ReferenceErrors, securityGroupDescriptor)
	}
}
