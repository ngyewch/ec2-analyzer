package analyzer

import (
	"cmp"
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"slices"
)

type Analyzer struct {
	ec2Service                  *ec2.Client
	rdsService                  *rds.Client
	securityGroupMap            map[string]types.SecurityGroup
	instances                   []Instance
	securityGroupReportEntryMap map[SecurityGroupDescriptor]*SecurityGroupReportEntry
}

func NewAnalyzer(ec2Service *ec2.Client, rdsService *rds.Client) *Analyzer {
	return &Analyzer{
		ec2Service: ec2Service,
		rdsService: rdsService,
	}
}

func (analyzer *Analyzer) Analyze(ctx context.Context) error {
	analyzer.instances = nil

	err := analyzer.describeSecurityGroups(ctx)
	if err != nil {
		return err
	}

	err = analyzer.describeEC2Instances(ctx)
	if err != nil {
		return err
	}

	err = analyzer.describeRDSInstances(ctx)
	if err != nil {
		return err
	}

	analyzer.securityGroupReportEntryMap = make(map[SecurityGroupDescriptor]*SecurityGroupReportEntry)
	//connectionMap := make(map[Instance][]Rule)
	for _, securityGroup := range analyzer.securityGroupMap {
		securityGroupReportEntry := analyzer.getSecurityGroupReportEntry(securityGroup)
		analyzer.processIpPermissions(securityGroupReportEntry, "inbound", securityGroup.IpPermissions)
		analyzer.processIpPermissions(securityGroupReportEntry, "outbound", securityGroup.IpPermissionsEgress)
	}

	for _, instance := range analyzer.instances {
		for _, securityGroupId := range instance.SecurityGroupIds() {
			securityGroup, ok := analyzer.securityGroupMap[securityGroupId]
			if !ok {
				continue
			}
			securityGroupReportEntry := analyzer.getSecurityGroupReportEntry(securityGroup)
			securityGroupReportEntry.AddUsedBy(instance)
		}
	}

	var securityGroupReportEntries []*SecurityGroupReportEntry
	for _, securityGroupReportEntry := range analyzer.securityGroupReportEntryMap {
		securityGroupReportEntries = append(securityGroupReportEntries, securityGroupReportEntry)
	}
	slices.SortFunc(securityGroupReportEntries, func(a *SecurityGroupReportEntry, b *SecurityGroupReportEntry) int {
		return cmp.Compare(a.Descriptor.GroupName, b.Descriptor.GroupName)
	})
	for _, securityGroupReportEntry := range securityGroupReportEntries {
		fmt.Printf("[%s %s]\n", securityGroupReportEntry.Descriptor.GroupId, securityGroupReportEntry.Descriptor.GroupName)
		if len(securityGroupReportEntry.UsedBy) > 0 {
			fmt.Println("Used by:")
			slices.SortFunc(securityGroupReportEntry.UsedBy, func(a Instance, b Instance) int {
				return cmp.Or(
					cmp.Compare(a.Type(), b.Type()),
					cmp.Compare(a.Name(), b.Name()),
					cmp.Compare(a.Id(), b.Id()),
				)
			})
			for _, usedBy := range securityGroupReportEntry.UsedBy {
				fmt.Printf("- %s\n", usedBy)
			}
		}
		if len(securityGroupReportEntry.ReferencedBy) > 0 {
			fmt.Println("Referenced by:")
			slices.SortFunc(securityGroupReportEntry.ReferencedBy, func(a Rule, b Rule) int {
				return cmp.Or(
					cmp.Compare(a.Type, b.Type),
					cmp.Compare(a.TrafficDescriptor.String(), b.TrafficDescriptor.String()),
					cmp.Compare(a.DeclaredBy.GroupName, b.DeclaredBy.GroupName),
				)
			})
			for _, referencedBy := range securityGroupReportEntry.ReferencedBy {
				fmt.Printf("- %s\n", referencedBy)
			}
		}
		fmt.Println()
	}

	return nil
}

func (analyzer *Analyzer) processIpPermissions(securityGroupReportEntry *SecurityGroupReportEntry, ruleType string, ipPermissions []types.IpPermission) {
	for _, ipPermission := range ipPermissions {
		// TODO IpRanges, Ipv6Ranges, PrefixListIds
		for _, userIdGroupPair := range ipPermission.UserIdGroupPairs {
			sourceSecurityGroup, ok := analyzer.securityGroupMap[*userIdGroupPair.GroupId]
			if !ok {
				securityGroupReportEntry.AddReferenceError(SecurityGroupDescriptor{
					GroupId:   *userIdGroupPair.GroupId,
					GroupName: *userIdGroupPair.GroupName,
				})
			} else {
				rule := toRule(ruleType, securityGroupReportEntry.Descriptor, ipPermission, userIdGroupPair)
				sourceSecurityGroupReportEntry := analyzer.getSecurityGroupReportEntry(sourceSecurityGroup)
				sourceSecurityGroupReportEntry.AddReferencedBy(rule)
			}
		}
	}
}

func (analyzer *Analyzer) getSecurityGroupReportEntry(securityGroup types.SecurityGroup) *SecurityGroupReportEntry {
	securityGroupDescriptor := toSecurityGroupDescriptor(securityGroup)
	securityGroupReportEntry, ok := analyzer.securityGroupReportEntryMap[securityGroupDescriptor]
	if !ok {
		securityGroupReportEntry = &SecurityGroupReportEntry{
			SecurityGroup: securityGroup,
			Descriptor:    securityGroupDescriptor,
		}
		analyzer.securityGroupReportEntryMap[securityGroupDescriptor] = securityGroupReportEntry
	}
	return securityGroupReportEntry
}

func (analyzer *Analyzer) getInstancesWithSecurityGroup(groupId string) []Instance {
	var instances []Instance
	for _, instance := range analyzer.instances {
		for _, securityGroupId := range instance.SecurityGroupIds() {
			if securityGroupId == groupId {
				instances = append(instances, instance)
				break
			}
		}
	}
	return instances
}

func (analyzer *Analyzer) describeSecurityGroups(ctx context.Context) error {
	securityGroupMap := make(map[string]types.SecurityGroup)
	input := &ec2.DescribeSecurityGroupsInput{}
	for {
		resp, err := analyzer.ec2Service.DescribeSecurityGroups(ctx, input)
		if err != nil {
			return err
		}
		for _, securityGroup := range resp.SecurityGroups {
			securityGroupMap[*securityGroup.GroupId] = securityGroup
		}
		if resp.NextToken == nil {
			break
		} else {
			input.NextToken = resp.NextToken
		}
	}
	analyzer.securityGroupMap = securityGroupMap
	return nil
}

func (analyzer *Analyzer) describeEC2Instances(ctx context.Context) error {
	input := &ec2.DescribeInstancesInput{}
	for {
		resp, err := analyzer.ec2Service.DescribeInstances(ctx, input)
		if err != nil {
			return err
		}
		for _, reservation := range resp.Reservations {
			for _, instance := range reservation.Instances {
				analyzer.instances = append(analyzer.instances, NewEC2Instance(instance, reservation))
			}
		}
		if resp.NextToken == nil {
			break
		} else {
			input.NextToken = resp.NextToken
		}
	}
	return nil
}

func (analyzer *Analyzer) describeRDSInstances(ctx context.Context) error {
	input := &rds.DescribeDBInstancesInput{}
	for {
		resp, err := analyzer.rdsService.DescribeDBInstances(ctx, input)
		if err != nil {
			return err
		}
		for _, instance := range resp.DBInstances {
			analyzer.instances = append(analyzer.instances, NewRDSInstance(instance))
		}
		if resp.Marker == nil {
			break
		} else {
			input.Marker = resp.Marker
		}
	}
	return nil
}
