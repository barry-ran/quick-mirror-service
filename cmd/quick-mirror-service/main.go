package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/barry-ran/quick-mirror-service/internal/access"
	"github.com/barry-ran/quick-mirror-service/internal/bootstrap"
	"github.com/barry-ran/quick-mirror-service/internal/catalog"
	"github.com/barry-ran/quick-mirror-service/internal/httpapi"
	"github.com/barry-ran/quick-mirror-service/internal/peerloom"
	"github.com/jackc/pgx/v5/pgxpool"
)

type config struct {
	HTTP              httpapi.BootstrapConfig
	Database          string
	ServiceCredential string
	Address           string
	CertificateFile   string
	KeyFile           string
	AccessKey         []byte
	APIConcurrency    int
	upstreamClient    *http.Client // 测试注入受信CA；生产始终使用系统信任与严格HTTPS。
}

func loadConfig() (config, error) {
	c := config{Database: os.Getenv("QM_DATABASE_URL"), ServiceCredential: os.Getenv("QM_PEERLOOM_SERVICE_CREDENTIAL"), Address: os.Getenv("QM_LISTEN_ADDRESS"), CertificateFile: os.Getenv("QM_TLS_CERT_FILE"), KeyFile: os.Getenv("QM_TLS_KEY_FILE")}
	c.HTTP.Identity = peerloom.IdentityConfig{Origin: os.Getenv("QM_PEERLOOM_ORIGIN"), TenantID: os.Getenv("QM_TENANT_ID"), PCApplicationID: os.Getenv("QM_PC_APPLICATION_ID"), MobileApplicationID: os.Getenv("QM_MOBILE_APPLICATION_ID")}
	c.HTTP.ServiceScope = os.Getenv("QM_SERVICE_SCOPE")
	if c.Address == "" {
		c.Address = "127.0.0.1:8443"
	}
	if _, _, err := net.SplitHostPort(c.Address); err != nil {
		return c, errors.New("INVALID_LISTEN_ADDRESS")
	}
	var err error
	c.HTTP.MaxConcurrent, err = positiveInt("QM_BOOTSTRAP_CONCURRENCY", 16)
	if err != nil {
		return c, err
	}
	c.HTTP.Burst, err = positiveInt("QM_BOOTSTRAP_BURST", 20)
	if err != nil {
		return c, err
	}
	rate, err := positiveInt("QM_BOOTSTRAP_RATE", 2)
	if err != nil {
		return c, err
	}
	c.HTTP.RequestsPerSecond = float64(rate)
	c.APIConcurrency, err = positiveInt("QM_API_CONCURRENCY", 64)
	if err != nil || c.APIConcurrency > 4096 {
		return c, errors.New("INVALID_RESOURCE_BUDGET")
	}
	c.AccessKey, err = readAccessKey(os.Getenv("QM_ACCESS_KEY_FILE"))
	if err != nil {
		return c, err
	}
	if c.Database == "" || c.CertificateFile == "" || c.KeyFile == "" {
		return c, errors.New("DATABASE_AND_TLS_CONFIGURATION_REQUIRED")
	}
	if _, err := peerloom.NewRegistrationClient(c.HTTP.Identity, c.ServiceCredential, nil); err != nil {
		return c, errors.New("INVALID_PEERLOOM_CONFIGURATION")
	}
	// 只校验配置，不向网络发送请求；实际 Store 在数据库初始化后构造。
	if _, err := httpapi.ValidateBootstrapConfig(c.HTTP); err != nil {
		return c, errors.New("INVALID_SERVICE_CONFIGURATION")
	}
	return c, nil
}

// 只读取运维提供的独立密钥；不自动生成/覆盖，不把内容放进错误或日志。
func readAccessKey(path string) ([]byte, error) {
	invalid := errors.New("ACCESS_KEY_FILE_REQUIRED")
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || (runtime.GOOS != "windows" && before.Mode().Perm()&0077 != 0) {
		return nil, invalid
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, invalid
	}
	defer file.Close()
	current, err := file.Stat()
	if err != nil || !os.SameFile(before, current) {
		return nil, invalid
	}
	data, err := io.ReadAll(io.LimitReader(file, 65))
	if err != nil || len(data) > 64 {
		return nil, invalid
	}
	text := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	key, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != text {
		return nil, invalid
	}
	return key, nil
}

func positiveInt(name string, fallback int) (int, error) {
	text := os.Getenv(name)
	if text == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(text)
	if err != nil || value < 1 {
		return 0, errors.New("INVALID_RESOURCE_BUDGET")
	}
	return value, nil
}

func databaseConfig(dsn string) (*pgxpool.Config, error) {
	c, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("INVALID_DATABASE_CONFIGURATION")
	}
	if c.ConnConfig.TLSConfig == nil || c.ConnConfig.TLSConfig.InsecureSkipVerify || len(c.ConnConfig.Fallbacks) > 0 {
		return nil, errors.New("DATABASE_VERIFY_FULL_TLS_REQUIRED")
	}
	c.MaxConns = 16
	c.MinConns = 0
	c.ConnConfig.ConnectTimeout = 5 * time.Second
	return c, nil
}

func serve(ctx context.Context, c config, migrate bool) error {
	dbConfig, err := databaseConfig(c.Database)
	if err != nil {
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, dbConfig)
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	defer pool.Close()
	check, cancel := context.WithTimeout(ctx, 5*time.Second)
	err = pool.Ping(check)
	cancel()
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	issuer, err := peerloom.NewRegistrationClient(c.HTTP.Identity, c.ServiceCredential, c.upstreamClient)
	if err != nil {
		return errors.New("INVALID_PEERLOOM_CONFIGURATION")
	}
	store, err := bootstrap.NewStore(pool, c.HTTP.ServiceScope, issuer)
	if err != nil {
		return errors.New("INVALID_SERVICE_CONFIGURATION")
	}
	directory, err := catalog.NewStore(pool, c.HTTP.ServiceScope, c.HTTP.Identity.TenantID)
	if err != nil {
		return errors.New("INVALID_SERVICE_CONFIGURATION")
	}
	verifier, err := peerloom.NewIdentityClient(c.HTTP.Identity, c.upstreamClient)
	if err != nil {
		return errors.New("INVALID_PEERLOOM_CONFIGURATION")
	}
	tokens, err := access.NewStore(pool, c.HTTP.ServiceScope, c.HTTP.Identity.TenantID, c.AccessKey, verifier)
	if err != nil {
		return errors.New("INVALID_SERVICE_CONFIGURATION")
	}
	if migrate {
		migration, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if directory.Migrate(migration) != nil || store.Migrate(migration) != nil || tokens.Migrate(migration) != nil {
			return errors.New("MIGRATION_FAILED")
		}
		return nil
	}
	var schemaReady bool
	check, cancel = context.WithTimeout(ctx, 5*time.Second)
	err = pool.QueryRow(check, `SELECT to_regclass('qm_bootstrap_intents') IS NOT NULL AND to_regclass('qm_access_tokens') IS NOT NULL AND to_regclass('qm_access_key_usage') IS NOT NULL AND to_regclass('qm_device_catalog') IS NOT NULL AND to_regclass('qm_device_boots') IS NOT NULL`).Scan(&schemaReady)
	cancel()
	if err != nil || !schemaReady {
		return errors.New("MIGRATION_REQUIRED")
	}
	pair, err := tls.LoadX509KeyPair(c.CertificateFile, c.KeyFile)
	if err != nil {
		return errors.New("TLS_KEY_PAIR_UNAVAILABLE")
	}
	handler, err := httpapi.NewBootstrapHandler(c.HTTP, store)
	if err != nil {
		return errors.New("INVALID_SERVICE_CONFIGURATION")
	}
	exchange, err := httpapi.NewExchangeHandler(tokens, directory, c.APIConcurrency)
	if err != nil {
		return errors.New("INVALID_SERVICE_CONFIGURATION")
	}
	devices, err := httpapi.NewCatalogHandler(tokens, directory, c.APIConcurrency)
	if err != nil {
		return errors.New("INVALID_SERVICE_CONFIGURATION")
	}
	routes := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/qm/v1/auth/pc/exchange", "/qm/v1/auth/device/exchange":
			exchange.ServeHTTP(w, r)
		case "/qm/v1/devices/resolve", "/qm/v1/device-self/status":
			devices.ServeHTTP(w, r)
		default:
			handler.ServeHTTP(w, r)
		}
	})
	server := &http.Server{Addr: c.Address, Handler: routes, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	maintenance, stopMaintenance := context.WithCancel(ctx)
	maintenanceDone := make(chan struct{})
	go func() {
		defer close(maintenanceDone)
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-maintenance.Done():
				return
			case <-ticker.C:
				cleanup, cancel := context.WithTimeout(maintenance, 5*time.Second)
				err := store.PurgeExpired(cleanup)
				if err == nil {
					err = tokens.PurgeExpired(cleanup)
				}
				cancel()
				if err != nil && maintenance.Err() == nil {
					fmt.Fprintln(os.Stderr, "SERVICE_EXPIRED_RECORD_CLEANUP_FAILED")
				}
			}
		}
	}()
	defer func() { stopMaintenance(); <-maintenanceDone }()
	finished := make(chan error, 1)
	go func() { finished <- server.ListenAndServeTLS("", "") }()
	select {
	case err := <-finished:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("HTTPS_SERVER_FAILED")
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if server.Shutdown(shutdown) != nil {
			server.Close()
		}
		<-finished
		return nil
	}
}

func main() {
	migrate := flag.Bool("migrate", false, "显式迁移独立业务数据库，不启动监听")
	flag.Parse()
	c, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := serve(ctx, c, *migrate); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
