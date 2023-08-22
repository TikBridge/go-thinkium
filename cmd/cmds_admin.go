package cmd

func init() {
	AllCommands.Put(
		&start{"start"},
		&stop{"stop"},
	)
}
