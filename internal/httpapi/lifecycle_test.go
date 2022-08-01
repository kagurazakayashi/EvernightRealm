package httpapi

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/config"
)

// lifecycleServer 建立供生命週期測試使用的 Server：自訂路由與監聽埠（0 表示由系統指派）。
// 路由以 srv.wrap 套用與正式路徑相同的中介層鏈，確保停止行為在真實鏈上受測。
func lifecycleServer(t *testing.T, mux *http.ServeMux, shutdownTimeoutMS int) (*Server, string) {
	t.Helper()

	cfg := config.Default()
	cfg.Server.Listen = "127.0.0.1:0"
	cfg.Server.ShutdownTimeoutMS = shutdownTimeoutMS
	srv := New(&cfg, testVersion, Deps{})
	srv.httpSrv.Handler = srv.wrap(mux)

	ln, err := srv.Listen()
	if err != nil {
		t.Fatalf("Listen 失敗: %v", err)
	}
	addr := ln.Addr().String()
	go func() {
		if err := srv.Serve(ln); err != nil {
			t.Errorf("Serve 失敗: %v", err)
		}
	}()
	return srv, addr
}

// waitForRefused 等待停止流程生效（監聽器關閉後新連線應被拒絕）。
func waitForRefused(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			return
		}
		_ = conn.Close()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("停止流程未在期限內停止接受新連線")
}

// assertPortReleased 確認監聽資源已釋放：同一地址可再次監聽。
func assertPortReleased(t *testing.T, addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("停止後連接埠 %s 應可再次監聽: %v", addr, err)
	}
	_ = ln.Close()
}

func TestShutdownTimeoutFromConfig(t *testing.T) {
	cfg := config.Default()
	cfg.Server.ShutdownTimeoutMS = 2500
	srv := New(&cfg, testVersion, Deps{})
	if got := srv.ShutdownTimeout(); got != 2500*time.Millisecond {
		t.Fatalf("ShutdownTimeout 應為 2.5s，實際 %v", got)
	}
}

func TestServeStopsGracefullyAndDrainsInFlightRequest(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	srv, addr := lifecycleServer(t, mux, 5000)

	type result struct {
		status int
		err    error
	}
	inflight := make(chan result, 1)
	go func() {
		resp, err := http.Get("http://" + addr + "/slow")
		if err != nil {
			inflight <- result{err: err}
			return
		}
		defer resp.Body.Close()
		inflight <- result{status: resp.StatusCode}
	}()
	<-started

	shutdownErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdownErr <- srv.Shutdown(ctx)
	}()

	// 停止流程開始後不再接受新連線，但進行中的請求應被等待完成。
	waitForRefused(t, addr)
	close(release)

	select {
	case r := <-inflight:
		if r.err != nil {
			t.Fatalf("優雅停止期間進行中的請求不應失敗: %v", r.err)
		}
		if r.status != http.StatusOK {
			t.Fatalf("進行中的請求狀態碼應為 200，實際 %d", r.status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("優雅停止應等待進行中的請求完成")
	}

	if err := <-shutdownErr; err != nil {
		t.Fatalf("Shutdown 應成功完成: %v", err)
	}
	assertPortReleased(t, addr)
}

func TestShutdownTimeoutThenCloseReleasesListener(t *testing.T) {
	started := make(chan struct{})
	never := make(chan struct{})
	defer close(never)
	mux := http.NewServeMux()
	mux.HandleFunc("/hang", func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-never
	})

	srv, addr := lifecycleServer(t, mux, 5000)

	go func() {
		resp, err := http.Get("http://" + addr + "/hang")
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	<-started

	// 處理器持續阻塞：優雅停止必然逾時，回傳期限錯誤。
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := srv.Shutdown(ctx); err == nil {
		t.Fatal("處理器持續阻塞時 Shutdown 應回傳逾時錯誤")
	}

	// 兵底：強制關閉連線，確保程序能結束並釋放監聽資源。
	if err := srv.Close(); err != nil {
		t.Fatalf("Close 應成功: %v", err)
	}
	assertPortReleased(t, addr)
}
