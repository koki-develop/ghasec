package diagnostic_test

import (
	"testing"

	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/stretchr/testify/assert"
)

func TestError_Error(t *testing.T) {
	e := &diagnostic.Error{Message: "something went wrong"}
	assert.Equal(t, "something went wrong", e.Error())
}

func TestError_ImplementsErrorInterface(t *testing.T) {
	var _ error = &diagnostic.Error{}
}
