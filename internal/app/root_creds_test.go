package app

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/auth"
	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
)

// 這一檔釘 Root 憑據存儲適配的三件事：
//   - Replace 成功＝檔案與記憶體同一時刻認新值（改密生效的定義就是這一句）；
//   - 環境變數覆蓋下 Replaceable 否、Replace 也拒，且一個字都不寫——
//     與 init-root「不做兩份 Root 的搬遷」同一口徑；
//   - 任何失敗路徑都不動記憶體現值：「覆寫失敗但進程已按新值驗口令」
//     是最難查的半套，必須在結構上不存在。
//
// 測試全部走本次專屬臨時目錄裡的配置副本，不觸碰任何真實部署檔案。

// mustHash 產生測試專屬的 Argon2id 編碼（低成本參數檔；值只活在測試進程裡）。
func mustHash(t *testing.T, password string) string {
	t.Helper()
	hash, err := credential.Hash(password, credential.TestParams)
	if err != nil {
		t.Fatalf("產生測試憑據失敗：%v", err)
	}
	return hash
}

// newTestConfigFile 在臨時目錄建立一份「已初始化 Root 憑據」的配置副本並回讀其現值。
func newTestConfigFile(t *testing.T, password string) (path, hash string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "config.yaml")
	seed := "server:\n  listen: \"127.0.0.1:5206\"\nsecurity:\n  session_ttl_hours: 24\n"
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatalf("建立測試配置失敗：%v", err)
	}
	hash = mustHash(t, password)
	if err := config.WriteRootPasswordHash(path, hash); err != nil {
		t.Fatalf("前置初始化失敗：%v", err)
	}
	return path, hash
}

// TestRootCredentialStoreReplaceLandsEverywhere 成功覆寫：CurrentHash、檔案現值
// 三者同步換到新雜湊；失敗的第二次（帶著已被換掉的現值）被 CAS 擋下且不動檔案。
func TestRootCredentialStoreReplaceLandsEverywhere(t *testing.T) {
	path, oldHash := newTestConfigFile(t, "root-old")
	rc := newRootCredentialStore(config.Config{})
	rc.path = path
	rc.current = oldHash

	newHash := mustHash(t, "root-new")
	if err := rc.Replace(oldHash, newHash); err != nil {
		t.Fatalf("覆寫失敗：%v", err)
	}
	if rc.CurrentHash() != newHash {
		t.Error("記憶體現值未隨覆寫更新——之後的 Root 登入會驗出一個查無此事的舊雜湊")
	}
	state, err := config.ReadRootFile(path)
	if err != nil || state.Hash != newHash {
		t.Errorf("檔案現值未更新：%+v err=%v", state, err)
	}

	// 帶著已被換掉的「舊現值」再打一次：CAS 必須擋下，兩個現值都不動。
	if err := rc.Replace(oldHash, mustHash(t, "root-third")); !errors.Is(err, auth.ErrRootCredentialStale) {
		t.Errorf("過期現值應回 ErrRootCredentialStale，實際 %v", err)
	}
	if rc.CurrentHash() != newHash {
		t.Error("被拒的覆寫動到了記憶體現值")
	}
	state, _ = config.ReadRootFile(path)
	if state.Hash != newHash {
		t.Error("被拒的覆寫動到了檔案")
	}
}

// TestRootCredentialStoreEnvOverrideBlocks 環境變數覆蓋時不可覆寫：
// 替身式的「假成功」在這裡比拒絕危險得多（寫進檔案的那份永遠不生效）。
func TestRootCredentialStoreEnvOverrideBlocks(t *testing.T) {
	path, oldHash := newTestConfigFile(t, "root-env")
	t.Setenv(config.RootPasswordHashEnvKey, mustHash(t, "root-env-override"))
	rc := newRootCredentialStore(config.Config{})
	rc.path = path
	rc.current = oldHash

	if rc.Replaceable() {
		t.Fatal("環境變數覆蓋下 Replaceable 必須為否")
	}
	if err := rc.Replace(oldHash, mustHash(t, "root-new")); !errors.Is(err, auth.ErrRootCredentialLocked) {
		t.Errorf("應回 ErrRootCredentialLocked，實際 %v", err)
	}
	if rc.CurrentHash() != oldHash {
		t.Error("被拒的覆寫動到了記憶體現值")
	}
	state, _ := config.ReadRootFile(path)
	if state.Hash != oldHash {
		t.Error("被拒的覆寫動到了檔案")
	}
}

// TestRootCredentialStoreFileMismatchIsStale 記憶體還相信舊值、檔案卻已被外部動作換掉：
// config 層的現值不符要翻成用例層的過期結論，且不動記憶體的信任。
func TestRootCredentialStoreFileMismatchIsStale(t *testing.T) {
	path, oldHash := newTestConfigFile(t, "root-drift")
	external := mustHash(t, "root-external")
	// 直接把檔案換到另一個值（模擬服務之外的部署動作）。
	if err := config.UpdateRootPasswordHash(path, oldHash, external); err != nil {
		t.Fatalf("外部動作前置失敗：%v", err)
	}
	rc := newRootCredentialStore(config.Config{})
	rc.path = path
	rc.current = oldHash

	if err := rc.Replace(oldHash, mustHash(t, "root-new")); !errors.Is(err, auth.ErrRootCredentialStale) {
		t.Errorf("檔案漂移應回 ErrRootCredentialStale，實際 %v", err)
	}
	if rc.CurrentHash() != oldHash {
		t.Error("覆寫失敗時記憶體現值必須原封不動")
	}
	state, _ := config.ReadRootFile(path)
	if state.Hash != external {
		t.Error("覆寫失敗時檔案必須維持外部動作的結果")
	}
}

// TestRootCredentialStoreMissingConfigKeepsMemory 配置檔案不存在（路徑壞、部署搬遷）：
// 覆寫失敗、記憶體現值不動——讀舊值繼續可登，寫新值整筆沒有發生。
func TestRootCredentialStoreMissingConfigKeepsMemory(t *testing.T) {
	rc := newRootCredentialStore(config.Config{})
	rc.path = filepath.Join(t.TempDir(), "missing", "config.yaml")
	rc.current = mustHash(t, "root-x")

	if err := rc.Replace(rc.current, mustHash(t, "root-y")); err == nil {
		t.Fatal("配置不可寫時覆寫必須失敗")
	}
	if rc.CurrentHash() == "" {
		t.Error("覆寫失敗不得清空記憶體現值")
	}
}
