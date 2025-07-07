package server

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"
	"github.com/tb0hdan/go-webfilter/pkg/firewall"
	"github.com/tb0hdan/go-webfilter/pkg/firewall/nft"
	"github.com/tb0hdan/go-webfilter/pkg/hooks"
	"github.com/tb0hdan/go-webfilter/pkg/proc"
	"github.com/tb0hdan/go-webfilter/pkg/utils"
)

type Server struct {
	Port        int
	HTTPSPort   int
	dump        bool
	logger      zerolog.Logger
	procLister  proc.Lister
	fw          firewall.Firewall
	serverHooks hooks.Hook
}

func (s *Server) SetHooks(serverHooks hooks.Hook) {
	if serverHooks == nil {
		s.logger.Warn().Msg("No serverHooks provided, using default serverHooks")
		s.serverHooks = &hooks.EmptyHookImpl{}
		return
	}
	s.serverHooks = serverHooks
	s.logger.Info().Msg("Hooks set for the server")
}

func (s *Server) IdentifyLocalAddr(c echo.Context) error {
	// Get the remote address from the request
	localAddr := c.Request().RemoteAddr
	if localAddr == "" {
		return c.String(http.StatusBadRequest, "Local address not found")
	}
	// Split the remote address into IP and port
	host, port, err := net.SplitHostPort(localAddr)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error splitting local address")
	}

	f, err := os.Open("/proc/net/tcp")
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error opening /proc/net/tcp")
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error reading /proc/net/tcp")
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		//   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
		if strings.HasPrefix(line, "sl") {
			continue
		}
		fields := strings.Fields(line)
		src, srcPort, err := utils.ParseHexAddr(fields[1])
		if err != nil {
			return c.String(http.StatusInternalServerError, "Error parsing local address")
		}
		dst, dstPort, err := utils.ParseHexAddr(fields[2])
		if err != nil {
			return c.String(http.StatusInternalServerError, "Error parsing remote address")
		}
		if src == host && fmt.Sprintf("%d", srcPort) == port {
			// Found the matching remote address
			s.logger.Info().Msgf("Local address identified: %s:%d\n", src, srcPort)
			uid, inode := fields[7], fields[9]
			procInfo, err := s.procLister.GetProcessInfoByInode(inode)
			if err != nil {
				return c.String(http.StatusInternalServerError, "Error getting process info by inode")
			}
			procInfo.UID = uid
			procInfo.SrcAddr = src
			procInfo.SrcPort = fmt.Sprintf("%d", srcPort)
			procInfo.DstAddr = dst
			procInfo.DstPort = fmt.Sprintf("%d", dstPort)
			procInfo.DstHost = c.Request().Host
			fmt.Printf("%+v", procInfo)
		}

	}
	return nil
}

func (s *Server) DumpRequest(req *http.Request) {
	if !s.dump {
		return
	}
	reqDump, err := httputil.DumpRequest(req, true)
	if err != nil {
		fmt.Println("Error dumping request:", err)
		return
	}
	fmt.Printf("Request: %s", reqDump)
}

func (s *Server) DumpResponse(rsp *http.Response) {
	if !s.dump {
		return
	}
	rspDump, err := httputil.DumpResponse(rsp, true)
	if err != nil {
		fmt.Println("Error dumping response:", err)
		return
	}
	fmt.Printf("Response: %s", rspDump)
}

func (s *Server) RegisterRoutes(e *echo.Echo) {
	e.GET("/", s.HandlePath)
	e.GET("/:path", s.HandlePath)
	//
	e.POST("/", s.HandlePath)
	e.POST("/:path", s.HandlePath)
	//
	e.PUT("/", s.HandlePath)
	e.PUT("/:path", s.HandlePath)
	//
	e.DELETE("/", s.HandlePath)
	e.DELETE("/:path", s.HandlePath)
	//
	e.PATCH("/", s.HandlePath)
	e.PATCH("/:path", s.HandlePath)
	//
	e.HEAD("/", s.HandlePath)
	e.HEAD("/:path", s.HandlePath)
	//
}

func (s *Server) Setup() {
	// Get a free port for the redirect
	redirectPort, err := utils.GetFreePort()
	if err != nil {
		fmt.Println("Error getting free port:", err)
		return
	}
	// Set the server port to the redirect port
	s.Port = redirectPort

	// Get a free port for HTTPS
	httpsPort, err := utils.GetFreePort()
	if err != nil {
		fmt.Println("Error getting free port for HTTPS:", err)
		return
	}
	s.HTTPSPort = httpsPort
	s.logger.Info().Msgf("HTTP server will listen on port %d", s.Port)
	s.logger.Info().Msgf("HTTPS server will listen on port %d", s.HTTPSPort)

	// Create firewall rules to redirect traffic
	if err := s.fw.InstallRules(redirectPort, httpsPort); err != nil {
		s.logger.Error().Err(err).Msg("Error installing firewall rules")
		return
	}
}

func (s *Server) Cleanup() {
	if err := s.fw.UninstallRules(); err != nil {
		s.logger.Error().Err(err).Msg("Error uninstalling firewall rules")
		return
	}
}

func New(logger zerolog.Logger, dump bool) *Server {
	procLister := proc.New(logger)
	return &Server{
		fw:         nft.New(logger),
		dump:       dump,
		logger:     logger,
		procLister: procLister,
	}
}
