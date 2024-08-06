package analyzer

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdsTypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/yassinebenaid/godump"
)

type Analyzer struct {
	ec2Service                  *ec2.Client
	rdsService                  *rds.Client
	securityGroupMap            map[string]types.SecurityGroup
	instances                   []types.Instance
	dbInstances                 []rdsTypes.DBInstance
	securityGroupReportEntryMap map[SecurityGroupDescriptor]*SecurityGroupReportEntry
}

func New(ec2Service *ec2.Client, rdsService *rds.Client) *Analyzer {
	return &Analyzer{
		ec2Service: ec2Service,
		rdsService: rdsService,
	}
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

func (analyzer *Analyzer) Analyze(ctx context.Context) error {
	err := analyzer.describeSecurityGroups(ctx)
	if err != nil {
		return err
	}

	err = analyzer.describeInstances(ctx)
	if err != nil {
		return err
	}

	err = analyzer.describeDBInstances(ctx)
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
		instanceDescriptor := toInstanceDescriptor(instance)

		connectionMap := make(map[string][]PortDescriptor)
		for _, securityGroupIdentifier := range instance.SecurityGroups {
			securityGroup, ok := analyzer.securityGroupMap[*securityGroupIdentifier.GroupId]
			if !ok {
				continue
			}

			securityGroupDescriptor := toSecurityGroupDescriptor(securityGroup)
			securityGroupReportEntry := analyzer.getSecurityGroupReportEntry(securityGroupDescriptor)
			securityGroupReportEntry.AddUsedBy(instanceDescriptor)

			for _, ipPermission := range securityGroup.IpPermissions {
				// TODO IpRanges, Ipv6Ranges, PrefixListIds
				for _, userIdGroupPair := range ipPermission.UserIdGroupPairs {
					sourceSecurityGroup, ok := analyzer.securityGroupMap[*userIdGroupPair.GroupId]
					if !ok {
						return fmt.Errorf("unknown security group '%s' is referred from security group '%s'",
							*userIdGroupPair.GroupId, *securityGroupIdentifier.GroupId)
					}

					portDescriptor := toPortDescriptor(securityGroup, sourceSecurityGroup, ipPermission)

					fromInstances := analyzer.getInstancesWithSecurityGroup(*userIdGroupPair.GroupId)
					for _, fromInstance := range fromInstances {
						connectionMap[*fromInstance.InstanceId] = append(connectionMap[*fromInstance.InstanceId], portDescriptor)
					}
				}
			}
		}
	}

	for _, securityGroupReportEntry := range analyzer.securityGroupReportEntryMap {
		fmt.Printf("[%s %s]\n", securityGroupReportEntry.Descriptor.GroupId, securityGroupReportEntry.Descriptor.GroupName)
		fmt.Println("Used by:")
		for _, usedBy := range securityGroupReportEntry.UsedBy {
			fmt.Printf("- %s %s\n", usedBy.InstanceId, usedBy.InstanceName)
		}
		fmt.Println("Referenced by:")
		for _, referencedBy := range securityGroupReportEntry.ReferencedBy {
			fmt.Printf("- %s\n", referencedBy)
		}
		fmt.Println()
	}

	for _, dbInstance := range analyzer.dbInstances {
		err = godump.Dump(dbInstance)
		if err != nil {
			return err
		}
	}

	return nil
}

func (analyzer *Analyzer) getInstancesWithSecurityGroup(groupId string) []types.Instance {
	var instances []types.Instance
	for _, instance := range analyzer.instances {
		for _, securityGroup := range instance.SecurityGroups {
			if *securityGroup.GroupId == groupId {
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

func (analyzer *Analyzer) describeInstances(ctx context.Context) error {
	var instances []types.Instance
	input := &ec2.DescribeInstancesInput{}
	for {
		resp, err := analyzer.ec2Service.DescribeInstances(ctx, input)
		if err != nil {
			return err
		}
		for _, reservation := range resp.Reservations {
			for _, instance := range reservation.Instances {
				instances = append(instances, instance)
			}
		}
		if resp.NextToken == nil {
			break
		} else {
			input.NextToken = resp.NextToken
		}
	}
	analyzer.instances = instances
	return nil
}

func (analyzer *Analyzer) describeDBInstances(ctx context.Context) error {
	var instances []rdsTypes.DBInstance
	input := &rds.DescribeDBInstancesInput{}
	for {
		resp, err := analyzer.rdsService.DescribeDBInstances(ctx, input)
		if err != nil {
			return err
		}
		for _, instance := range resp.DBInstances {
			instances = append(instances, instance)
		}
		if resp.Marker == nil {
			break
		} else {
			input.Marker = resp.Marker
		}
	}
	analyzer.dbInstances = instances
	return nil
}

func getTagByName(tags []types.Tag, name string) string {
	for _, tag := range tags {
		if *tag.Key == name {
			return *tag.Value
		}
	}
	return ""
}
