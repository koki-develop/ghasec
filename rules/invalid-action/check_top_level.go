package invalidaction

import (
	"fmt"

	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/workflow"
)

func checkTopLevelKeys(mapping workflow.Mapping) []*diagnostic.Error {
	var errs []*diagnostic.Error
	for _, entry := range mapping.Values {
		key := entry.Key.GetToken().Value
		if !knownTopLevelKeys[key] {
			errs = append(errs, &diagnostic.Error{
				Token:   entry.Key.GetToken(),
				Message: fmt.Sprintf("unknown key %q", key),
			})
		}
	}

	if mapping.FindKey("runs") == nil {
		errs = append(errs, &diagnostic.Error{
			Token:   mapping.FirstToken(),
			Message: "\"runs\" is required",
		})
	}

	return errs
}
