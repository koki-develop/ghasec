package invalidaction

var knownJSRunsKeys = map[string]bool{
	"using": true, "main": true, "pre": true, "pre-if": true, "post": true, "post-if": true,
}

var knownCompositeRunsKeys = map[string]bool{
	"using": true, "steps": true,
}

var knownDockerRunsKeys = map[string]bool{
	"using": true, "image": true, "env": true, "entrypoint": true,
	"pre-entrypoint": true, "pre-if": true, "post-entrypoint": true, "post-if": true, "args": true,
}

var knownUsingValues = map[string]bool{
	"composite": true, "node12": true, "node16": true, "node20": true, "node24": true, "docker": true,
}

var jsUsingValues = map[string]bool{
	"node12": true, "node16": true, "node20": true, "node24": true,
}

var knownCompositeStepKeys = map[string]bool{
	"run": true, "shell": true, "uses": true, "with": true, "name": true,
	"id": true, "if": true, "env": true, "continue-on-error": true, "working-directory": true,
}

var knownInputKeys = map[string]bool{
	"description": true, "required": true, "default": true, "deprecationMessage": true,
}

var knownOutputKeys = map[string]bool{
	"description": true,
}

var knownCompositeOutputKeys = map[string]bool{
	"description": true, "value": true,
}
