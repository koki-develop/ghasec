package invalidaction

import (
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

func checkTopLevelKeys(mapping workflow.Mapping) []*diagnostic.Error {
	errs := rules.CheckUnknownKeys(mapping, knownTopLevelKeys)

	if mapping.FindKey("runs") == nil {
		errs = append(errs, &diagnostic.Error{
			Token:   mapping.FirstToken(),
			Message: "\"runs\" is required",
		})
	}

	return errs
}
