package cmd

var (
	AllCommands = new(Cmds)
)

func init() {
	_ = AllCommands.Put(
		&join{"join"},
		&queue{"queue"},
		&status{"status"},
		&synccmd{"sync"},
		&replay{"replay"},
		&cursorto{"cursorto"},
		&rebuild{"rebuild"},
		&listtxs{"listtxs"},
		&listacs{"listacs"},
		&listrrs{"listrrs"},
		&listvccs{"listvccs"},
		&listcccs{"listcccs"},
		&snapshot{"snapshot"},
		// &sendSyncFinish{"sendsyncfinish"},
	)
}
