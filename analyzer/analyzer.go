package analyzer

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
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
	for _, securityGroup := range analyzer.securityGroupMap {
		securityGroupDescriptor := toSecurityGroupDescriptor(securityGroup)
		securityGroupReportEntry := analyzer.getSecurityGroupReportEntry(securityGroupDescriptor)

		for _, ipPermission := range securityGroup.IpPermissions {
			// TODO IpRanges, Ipv6Ranges, PrefixListIds
			for _, userIdGroupPair := range ipPermission.UserIdGroupPairs {
				sourceSecurityGroup, ok := analyzer.securityGroupMap[*userIdGroupPair.GroupId]
				if !ok {
					securityGroupReportEntry.AddReferenceError(SecurityGroupDescriptor{
						GroupId:   *userIdGroupPair.GroupId,
						GroupName: *userIdGroupPair.GroupName,
					})
				} else {
					sourceSecurityGroupDescriptor := toSecurityGroupDescriptor(sourceSecurityGroup)
					portDescriptor := toPortDescriptor(securityGroup, sourceSecurityGroup, ipPermission)

					sourceSecurityGroupReportEntry := analyzer.getSecurityGroupReportEntry(sourceSecurityGroupDescriptor)
					sourceSecurityGroupReportEntry.AddReferencedBy(portDescriptor)
				}
			}
		}
	}

	for _, instance := range analyzer.instances {
		connectionMap := make(map[string][]PortDescriptor)
		for _, securityGroupId := range instance.SecurityGroupIds() {
			securityGroup, ok := analyzer.securityGroupMap[securityGroupId]
			if !ok {
				continue
			}

			securityGroupDescriptor := toSecurityGroupDescriptor(securityGroup)
			securityGroupReportEntry := analyzer.getSecurityGroupReportEntry(securityGroupDescriptor)
			securityGroupReportEntry.AddUsedBy(instance)

			for _, ipPermission := range securityGroup.IpPermissions {
				// TODO IpRanges, Ipv6Ranges, PrefixListIds
				for _, userIdGroupPair := range ipPermission.UserIdGroupPairs {
					sourceSecurityGroup, ok := analyzer.securityGroupMap[*userIdGroupPair.GroupId]
					if !ok {
						continue
					}
					portDescriptor := toPortDescriptor(securityGroup, sourceSecurityGroup, ipPermission)
					fromInstances := analyzer.getInstancesWithSecurityGroup(*userIdGroupPair.GroupId)
					for _, fromInstance := range fromInstances {
						connectionMap[fromInstance.Id()] = append(connectionMap[fromInstance.Id()], portDescriptor)
					}
				}
			}
		}
	}

	for _, securityGroupReportEntry := range analyzer.securityGroupReportEntryMap {
		fmt.Printf("[%s %s]\n", securityGroupReportEntry.Descriptor.GroupId, securityGroupReportEntry.Descriptor.GroupName)
		fmt.Println("Used by:")
		for _, usedBy := range securityGroupReportEntry.UsedBy {
			fmt.Printf("- %s\n", usedBy)
		}
		fmt.Println("Referenced by:")
		for _, referencedBy := range securityGroupReportEntry.ReferencedBy {
			fmt.Printf("- %s\n", referencedBy)
		}
		fmt.Println()
	}

	return nil
}

func (analyzer *Analyzer) getSecurityGroupReportEntry(securityGroupDescriptor SecurityGroupDescriptor) *SecurityGroupReportEntry {
	securityGroupReportEntry, ok := analyzer.securityGroupReportEntryMap[securityGroupDescriptor]
	if !ok {
		securityGroupReportEntry = &SecurityGroupReportEntry{
			Descriptor: securityGroupDescriptor,
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
