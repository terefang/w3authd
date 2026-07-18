package server

import (
	"context"
	"embed"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"w3authproxy/pkg/login"
	"w3authproxy/pkg/overlayfs"

	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

type HttpServerContext struct {
	Context         context.Context
	Muxer           *http.ServeMux
	Svc             *http.Server
	CookieName      string
	PathPrefix      string
	ValidSessions   map[string][]string
	SessionLifetime int
	Fs              http.FileSystem
	Limiter         *rate.Limiter
	LoginDomains    []login.LoginContext
	AuthUserHeader  string
	AuthRolesHeader string
	TemplateOverlay string
}

func (s *HttpServerContext) SetSessionLifetime(n int) {
	s.SessionLifetime = n
}

func (s *HttpServerContext) SetPathPrefix(n string) {
	s.PathPrefix = n
}

func (s *HttpServerContext) SetCookieName(n string) {
	s.CookieName = n
}

func NewHttpServerContext() *HttpServerContext {
	c := &HttpServerContext{}
	c.LoginDomains = make([]login.LoginContext, 0)
	return c
}

func (s *HttpServerContext) AddLoginDomain(loginContext login.LoginContext) {
	s.LoginDomains = append(s.LoginDomains, loginContext)
}

func (s *HttpServerContext) LogS(p ...string) {
	log.Println(p)
}

func (s *HttpServerContext) LogR(r *http.Request, p string) {
	log.Printf("%s %s - %s", r.Method, r.URL, p)
}

func (s *HttpServerContext) LogFmtR(r *http.Request, _fmt string, _args ...interface{}) {
	log.Printf("%s %s - "+_fmt, r.Method, r.URL, _args)
}

func (s *HttpServerContext) Init() {
	//s.NotifyContext, _ = signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	s.Muxer = http.NewServeMux()
	s.SetCookieName("AUTHSESSION")
	s.SetPathPrefix("")
	s.ValidSessions = make(map[string][]string)
	s.Limiter = rate.NewLimiter(1, 5)
	s.Context = context.Background()
}

func (s *HttpServerContext) SetHandler(path string, f func(*HttpServerContext, http.ResponseWriter, *http.Request)) {
	s.Muxer.HandleFunc(s.PathPrefix+path, func(w http.ResponseWriter, r *http.Request) {
		f(s, w, r)
	})
}

func (s *HttpServerContext) RunAndServe(hostAddr string) {
	s.Svc = &http.Server{
		Addr:    hostAddr,
		Handler: s.Muxer,
	}

	if err := s.Svc.ListenAndServe(); err != nil && errors.Is(err, http.ErrServerClosed) {
		s.LogS("server closed")
	} else {
		s.LogS(err.Error())
	}
}

func (s *HttpServerContext) RegisterHandlers() {
	s.SetHandler("/validate", HandleValidationFunction)
	s.SetHandler("/auth", HandleLoginFunction)
	s.SetHandler("/logout", HandleLogoutFunction)
	s.SetHandler("/logout/", HandleLogoutFunction)

	var _httpFs http.FileSystem = nil
	if s.TemplateOverlay != "" {
		log.Printf("Using templates from %s as overlay", s.TemplateOverlay)
		_httpFs = http.FS(
			overlayfs.From(
				StaticFiles,
				os.DirFS(s.TemplateOverlay),
			))
	} else {
		log.Println("Using templates from embedded.")
		_httpFs = http.FS(StaticFiles)
	}

	_fs := http.FileServer(_httpFs)
	s.Muxer.Handle(s.PathPrefix+"/login/", http.StripPrefix(s.PathPrefix+"/login/", neuter(_fs)))

	s.Muxer.Handle("/", http.RedirectHandler(s.PathPrefix+"/login", http.StatusFound))
}

func (s *HttpServerContext) AddSessionCookie(w http.ResponseWriter, r *http.Request, usr string, roles []string) {
	_uuid, _ := uuid.NewRandom()

	cookie := http.Cookie{
		Name:     s.CookieName,
		Value:    _uuid.String(),
		Path:     "/",
		MaxAge:   s.SessionLifetime,
		HttpOnly: true,
		Secure:   true,
	}
	http.SetCookie(w, &cookie)

	s.ValidSessions[cookie.Value] = append([]string{usr}, roles...)
}

func (s *HttpServerContext) SetAuthUserHeader(h string) {
	s.AuthUserHeader = h
}

func (s *HttpServerContext) SetAuthRolesHeader(h string) {
	s.AuthRolesHeader = h
}

func (s *HttpServerContext) SetTemplateOverlay(p string) {
	s.TemplateOverlay = p
}

func neuter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func HandleValidationFunction(s *HttpServerContext, w http.ResponseWriter, r *http.Request) {
	_c, _err := r.Cookie(s.CookieName)
	if _err != nil {
		s.LogFmtR(r, "Cookie %s not found", r.URL.Path)
		if _werr := s.Limiter.Wait(s.Context); _werr != nil {
			w.WriteHeader(http.StatusTooManyRequests)
		} else {
			w.WriteHeader(http.StatusForbidden)
		}
		return
	}

	_roles, _ok := s.ValidSessions[_c.Value]
	if !_ok {
		s.LogFmtR(r, "Session %s not valid", r.URL.Path)
		w.WriteHeader(http.StatusUnauthorized)
	} else if _roles == nil {
		s.LogFmtR(r, "Session %s not expired.", r.URL.Path)
		w.WriteHeader(http.StatusUnauthorized)
	} else {
		w.Header().Set(s.AuthUserHeader, _roles[0])
		w.Header().Set(s.AuthRolesHeader, strings.Join(_roles, ","))

		s.LogFmtR(r, "Session %s valid %s", r.URL.Path, _c.Value)
		w.WriteHeader(http.StatusOK)
	}
}

//go:embed assets *.html *.jpg
var StaticFiles embed.FS

func HandleLogin(s *HttpServerContext, w http.ResponseWriter, r *http.Request) bool {

	_usr := r.FormValue("s_username")
	_pwd := r.FormValue("s_password")
	for _, _lh := range s.LoginDomains {
		_lhandled, _roles, _lerr := _lh.HandleLogin(_usr, _pwd)
		if _lerr != nil {
			s.LogR(r, _lerr.Error())
			return false
		} else if _lhandled {
			s.AddSessionCookie(w, r, _usr, _roles)
			return true
		}
	}
	return false
}

func HandleLoginFunction(s *HttpServerContext, w http.ResponseWriter, r *http.Request) {
	if _werr := s.Limiter.Wait(s.Context); _werr != nil {
		w.WriteHeader(http.StatusTooManyRequests)
	} else if HandleLogin(s, w, r) {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	} else {
		http.Redirect(w, r, "./login/error.html", http.StatusTemporaryRedirect)
	}
}

func HandleLogoutFunction(s *HttpServerContext, w http.ResponseWriter, r *http.Request) {
	_c, _err := r.Cookie(s.CookieName)
	if _err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	_, _ok := s.ValidSessions[_c.Value]
	if !_ok {
		w.WriteHeader(http.StatusUnauthorized)
	}

	s.ValidSessions[_c.Value] = nil

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}
