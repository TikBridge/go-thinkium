package cmd

import (
	"github.com/ThinkiumGroup/go-thinkium/models"
)

type start struct {
	SingleCmd
}

func (s start) Run(line string, ctx RunContext) error {
	mm, err := models.CreateStartMessage()
	if err != nil {
		return err
	}
	ctx.Eventer().Post(mm)
	return nil
}

type stop struct {
	SingleCmd
}

func (s stop) Run(line string, ctx RunContext) error {
	mm, err := models.CreateStopMessage()
	if err != nil {
		return err
	}
	ctx.Eventer().Post(mm)
	return nil
}
