package hooks

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

type Hook interface {
	BeforeRequest(c echo.Context) error
	AfterRequest(c echo.Context, rsp *http.Response) error
}
