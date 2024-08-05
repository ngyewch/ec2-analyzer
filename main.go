package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/urfave/cli/v2"
	"log"
	"os"
	"runtime/debug"
)

func main() {
	app := &cli.App{
		Name:   "ec2-analyzer",
		Usage:  "EC2 Analyzer",
		Action: doRun,
	}

	buildInfo, _ := debug.ReadBuildInfo()
	if buildInfo != nil {
		app.Version = buildInfo.Main.Version
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func doRun(cCtx *cli.Context) error {
	cfg, err := config.LoadDefaultConfig(cCtx.Context)
	if err != nil {
		return err
	}
	ec2Service := ec2.NewFromConfig(cfg)

	securityGroupMap := make(map[string]types.SecurityGroup)
	{
		resp, err := ec2Service.DescribeSecurityGroups(cCtx.Context, &ec2.DescribeSecurityGroupsInput{})
		if err != nil {
			return err
		}
		for {
			for _, securityGroup := range resp.SecurityGroups {
				securityGroupMap[*securityGroup.GroupId] = securityGroup
			}
			if resp.NextToken == nil {
				break
			} else {
				resp, err = ec2Service.DescribeSecurityGroups(cCtx.Context, &ec2.DescribeSecurityGroupsInput{
					NextToken: resp.NextToken,
				})
				if err != nil {
					return err
				}
			}
		}
	}

	resp, err := ec2Service.DescribeInstances(cCtx.Context, &ec2.DescribeInstancesInput{})
	if err != nil {
		return err
	}
	for {
		for _, reservation := range resp.Reservations {
			for _, instance := range reservation.Instances {
				var name string
				for _, tag := range instance.Tags {
					if *tag.Key == "Name" {
						name = *tag.Value
						break
					}
				}
				/*
					for _, securityGroup := range instance.SecurityGroups {
					}
				*/
				fmt.Printf("%s %s\n", *instance.InstanceId, name)
			}
		}
		if resp.NextToken == nil {
			break
		} else {
			resp, err = ec2Service.DescribeInstances(cCtx.Context, &ec2.DescribeInstancesInput{
				NextToken: resp.NextToken,
			})
			if err != nil {
				return err
			}
		}
	}
	return nil
}
