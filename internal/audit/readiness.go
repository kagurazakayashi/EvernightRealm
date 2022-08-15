package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
)

// rootAuditTable 是 Root 作用域的落點表名。
//
// 它與 Scope.table() 同源：這個判斷要認的就是「那一張表」，寫成兩份字串遲早會分家。
const rootAuditTable = "root_audit"

// RootTableReady 回報這個資料庫裡 Root 層審計的落點是否已經存在。
//
// 存在的理由：一次性命令（例如 Root 初始化）必須在「碰組態檔之前」就知道審計寫不寫得進去。
// 資料庫的結構版本低於建立 root_audit 的那一支遷移時，Append 會以「沒有這張表」失敗，
// 而那時候憑據已經落地、記錄卻留不下——這個落差只能事先問出來，事後補不回來。
//
// 只問「表在不在」，不問結構長什麼樣子：結構是否可用由 Append 自己與資料庫的 CHECK
// 負責（規格 §25.3 的只追加約束就寫在那裡），這一層不複製那份判定。
func RootTableReady(ctx context.Context, q database.Querier) (bool, error) {
	if q == nil {
		return false, errors.New("audit: 檢查 Root 審計落點需要一個查詢介面")
	}
	var name string
	err := q.QueryRowContext(ctx,
		"SELECT name FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1", rootAuditTable).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("audit: 檢查 Root 審計落點失敗: %w", err)
	}
	return name == rootAuditTable, nil
}
