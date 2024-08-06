package main

import (
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/ngyewch/ec2-analyzer/analyzer"
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
	rdsService := rds.NewFromConfig(cfg)

	a := analyzer.NewAnalyzer(ec2Service, rdsService)
	return a.Analyze(cCtx.Context)
}
