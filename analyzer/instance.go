package analyzer

import (
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	rdsTypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

type Instance interface {
	fmt.Stringer

	Type() string
	Id() string
	Name() string
	Tag(name string) string
	SecurityGroupIds() []string
}

type EC2Instance struct {
	instance    types.Instance
	reservation types.Reservation
}

func NewEC2Instance(instance types.Instance, reservation types.Reservation) *EC2Instance {
	return &EC2Instance{
		instance:    instance,
		reservation: reservation,
	}
}

func (ec2Instance *EC2Instance) Type() string {
	return "EC2"
}

func (ec2Instance *EC2Instance) Id() string {
	if ec2Instance.instance.InstanceId != nil {
		return *ec2Instance.instance.InstanceId
	}
	return ""
}

func (ec2Instance *EC2Instance) Name() string {
	return ec2Instance.Tag("Name")
}

func (ec2Instance *EC2Instance) Tag(name string) string {
	for _, tag := range ec2Instance.instance.Tags {
		if (tag.Key != nil) && (*tag.Key == name) && (tag.Value != nil) {
			return *tag.Value
		}
	}
	return ""
}

func (ec2Instance *EC2Instance) SecurityGroupIds() []string {
	var securityGroupIds []string
	for _, securityGroupIdentifiers := range ec2Instance.instance.SecurityGroups {
		securityGroupIds = append(securityGroupIds, *securityGroupIdentifiers.GroupId)
	}
	return securityGroupIds
}

func (ec2Instance *EC2Instance) String() string {
	return fmt.Sprintf("%s %s %s", ec2Instance.Type(), ec2Instance.Id(), ec2Instance.Name())
}

type RDSInstance struct {
	instance rdsTypes.DBInstance
}

func NewRDSInstance(instance rdsTypes.DBInstance) *RDSInstance {
	return &RDSInstance{
		instance: instance,
	}
}

func (rdsInstance *RDSInstance) Type() string {
	return "RDS"
}

func (rdsInstance *RDSInstance) Id() string {
	if rdsInstance.instance.DBInstanceIdentifier != nil {
		return *rdsInstance.instance.DBInstanceIdentifier
	}
	return ""
}

func (rdsInstance *RDSInstance) Name() string {
	return rdsInstance.Tag("Name")
}

func (rdsInstance *RDSInstance) Tag(name string) string {
	for _, tag := range rdsInstance.instance.TagList {
		if (tag.Key != nil) && (*tag.Key == name) && (tag.Value != nil) {
			return *tag.Value
		}
	}
	return ""
}

func (rdsInstance *RDSInstance) SecurityGroupIds() []string {
	var securityGroupIds []string
	for _, vpcSecurityGroupMembership := range rdsInstance.instance.VpcSecurityGroups {
		if (vpcSecurityGroupMembership.Status != nil) && (*vpcSecurityGroupMembership.Status == "active") {
			securityGroupIds = append(securityGroupIds, *vpcSecurityGroupMembership.VpcSecurityGroupId)
		}
	}
	return securityGroupIds
}

func (rdsInstance *RDSInstance) String() string {
	return fmt.Sprintf("%s %s", rdsInstance.Type(), rdsInstance.Id())
}
