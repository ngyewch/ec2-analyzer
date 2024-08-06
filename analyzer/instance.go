package analyzer

import (
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	rdsTypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

type Instance interface {
	fmt.Stringer

	GetType() string
	GetId() string
	GetName() string
	GetTag(name string) string
	GetSecurityGroupIds() []string
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

func (ec2Instance *EC2Instance) GetType() string {
	return "EC2"
}

func (ec2Instance *EC2Instance) GetId() string {
	if ec2Instance.instance.InstanceId != nil {
		return *ec2Instance.instance.InstanceId
	}
	return ""
}

func (ec2Instance *EC2Instance) GetName() string {
	return ec2Instance.GetTag("Name")
}

func (ec2Instance *EC2Instance) GetTag(name string) string {
	for _, tag := range ec2Instance.instance.Tags {
		if (tag.Key != nil) && (*tag.Key == name) && (tag.Value != nil) {
			return *tag.Value
		}
	}
	return ""
}

func (ec2Instance *EC2Instance) GetSecurityGroupIds() []string {
	var securityGroupIds []string
	for _, securityGroupIdentifiers := range ec2Instance.instance.SecurityGroups {
		securityGroupIds = append(securityGroupIds, *securityGroupIdentifiers.GroupId)
	}
	return securityGroupIds
}

func (ec2Instance *EC2Instance) String() string {
	return fmt.Sprintf("%s %s %s", ec2Instance.GetType(), ec2Instance.GetId(), ec2Instance.GetName())
}

type RDSInstance struct {
	instance rdsTypes.DBInstance
}

func NewRDSInstance(instance rdsTypes.DBInstance) *RDSInstance {
	return &RDSInstance{
		instance: instance,
	}
}

func (rdsInstance *RDSInstance) GetType() string {
	return "RDS"
}

func (rdsInstance *RDSInstance) GetId() string {
	if rdsInstance.instance.DBName != nil {
		return *rdsInstance.instance.DBName
	}
	return ""
}

func (rdsInstance *RDSInstance) GetName() string {
	return rdsInstance.GetId()
}

func (rdsInstance *RDSInstance) GetTag(name string) string {
	for _, tag := range rdsInstance.instance.TagList {
		if (tag.Key != nil) && (*tag.Key == name) && (tag.Value != nil) {
			return *tag.Value
		}
	}
	return ""
}

func (rdsInstance *RDSInstance) GetSecurityGroupIds() []string {
	var securityGroupIds []string
	for _, vpcSecurityGroupMembership := range rdsInstance.instance.VpcSecurityGroups {
		if (vpcSecurityGroupMembership.Status != nil) && (*vpcSecurityGroupMembership.Status == "active") {
			securityGroupIds = append(securityGroupIds, *vpcSecurityGroupMembership.VpcSecurityGroupId)
		}
	}
	return securityGroupIds
}

func (rdsInstance *RDSInstance) String() string {
	return fmt.Sprintf("%s %s", rdsInstance.GetType(), rdsInstance.GetId())
}
