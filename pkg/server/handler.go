package server

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/labstack/echo/v4"
)

func (s *Server) HandlePath(c echo.Context) error {
	var (
		err     error
		reqBody []byte
	)
	// Extract the path parameter
	path := c.Param("path")
	if path == "" {
		// If no path parameter is provided, use the root path
		path = "/"
	}
	qs := c.Request().URL.RawQuery
	if len(qs) > 0 {
		// If there are query parameters, append them to the path
		path += "?" + qs
	}
	if err := s.IdentifyLocalAddr(c); err != nil {
		return c.String(http.StatusInternalServerError, "Error identifying local address")
	}
	// Run hooks before processing the request
	if err := s.serverHooks.BeforeRequest(c); err != nil {
		s.logger.Error().Err(err).Msg("Error running BeforeRequest hook")
		return c.String(http.StatusInternalServerError, "Error processing request")
	}
	// Construct the full URL to fetch
	url := fmt.Sprintf("%s://%s/%s", c.Scheme(), c.Request().Host, path)
	if c.Request().Method != http.MethodGet {
		// prepare body for non-GET requests
		reqBody, err = io.ReadAll(c.Request().Body)
		if err != nil {
			return c.String(http.StatusInternalServerError, "Error reading request body")
		}
	}
	// Keep-alive connections are using separate context, so we need to create a new request
	req, err := http.NewRequestWithContext(c.Request().Context(), c.Request().Method, url, bytes.NewReader(reqBody))
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error creating request")
	}
	// Copy headers from the original request
	for name, values := range c.Request().Header {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	// Dump the request if dump is enabled
	s.DumpRequest(req)
	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.logger.Error().Err(err).Msgf("Error executing request: %s", url)
		return c.String(http.StatusInternalServerError, "Error making request")
	}
	defer func() {
		_ = rsp.Body.Close()
	}()
	// Run hooks after processing the request
	if err := s.serverHooks.AfterRequest(c, rsp); err != nil {
		s.logger.Error().Err(err).Msg("Error running AfterRequest hook")
		return c.String(http.StatusInternalServerError, "Error processing request")
	}
	// Dump the request and response if dump is enabled
	s.DumpResponse(rsp)
	// Copy headers from the original request
	for name, values := range rsp.Header {
		for _, value := range values {
			c.Response().Header().Set(name, value)
		}
	}
	scanner := bufio.NewScanner(rsp.Body)
	for scanner.Scan() {
		line := scanner.Bytes()
		written, err := c.Response().Write(line)
		if err != nil {
			s.logger.Error().Err(err).Msg("Error writing response")
			break
		}
		if written < len(line) {
			s.logger.Error().Err(err).Msg("Error writing response")
			break
		}
		c.Response().Flush()
	}
	return nil
}
