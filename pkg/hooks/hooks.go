package hooks

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"
)

type EmptyHookImpl struct {
}

func (e *EmptyHookImpl) AfterRequest(c echo.Context, rsp *http.Response) error {
	return nil
}

func (e *EmptyHookImpl) BeforeRequest(c echo.Context) error {
	return nil
}

type HookImpl struct {
}

func (h *HookImpl) AfterRequest(c echo.Context, rsp *http.Response) error {
	return nil
}

func (h *HookImpl) BeforeRequest(c echo.Context) error {
	return nil
}

func New(logger zerolog.Logger) Hook {
	return &HookImpl{}
}
