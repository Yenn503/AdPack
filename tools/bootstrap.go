package tools

func RegisterBuiltinTools(r *Registry) {
	// NetExec is not registered via Tool interface — it has a different
	// Run signature (NetExecTarget instead of ExecutionRequest) and
	// provides transport-layer operations (PutFile/GetFile/EnumUsers)
	// rather than a self-contained capability.
	r.RegisterTool(GoMimikatz)
	r.RegisterTool(Nanodump)
	r.RegisterTool(UnDefend)
	r.RegisterTool(BlueHammer)
	r.RegisterTool(Donut)
	r.RegisterTool(ScareCrow)
	r.RegisterTool(SysWhispers)
	r.RegisterTool(LDAP)
	r.RegisterTool(PhantomKiller)
	r.RegisterTool(MiniPlasma)
}

func RegisterBuiltinExecutors(r *Registry) {
	r.RegisterExecutor("local", NewLocalExecutor(r))
}
