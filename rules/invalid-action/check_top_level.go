package invalidaction

import (
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

func checkTopLevelKeys(mapping workflow.Mapping) []*diagnostic.Error {
	var errs []*diagnostic.Error

	if mapping.FindKey("runs") == nil {
		errs = append(errs, &diagnostic.Error{
			Token:   mapping.FirstToken(),
			Message: "\"runs\" is required",
		})
	}

	errs = append(errs, rules.CheckUnknownKeys(mapping, knownTopLevelKeys)...)

	return errs
}
