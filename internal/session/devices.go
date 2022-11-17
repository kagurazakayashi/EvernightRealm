// devices.go 是「我的裝置」的讀寫落點：列舉某個受信主體名下的全部會話、
// 按歸屬定向撤銷其中一枚。
//
// 為什麼裝置清單不需要另一張 devices 表：sessions 行的 device_id 就是使用者可見的
// 裝置標識（遷移 0004 的三個標識分工），一行只可能來自一次登入，因此裝置清單的答案
// 本來就能由會話行讀出來——多一張表就多一個可以和事實不一致的地方（見 internal/session/device.go
// 檔首說明）。這裡刻意把「列舉」與「撤銷」放在一起，是因為它們共用同一條主體邊界
// （subjectFilter）：清單看到的範圍與撤銷能觸及的範圍必須逐字相同，否則會出現
// 「列得出來卻撤不掉」或反過來「撤掉了沒列出的東西」這種越權缺口。
//
// 收錄範圍（使用者批准的產品決定）：不只「此刻還換得出身份」的會話，也包含仍留在
// 資料庫裡的失效行（已撤銷、已過絕對期限，但尚未被 Cleanup 依寬限期刪除）。
// 這正是 R1-015 保留 cleanup_grace 的對象：讓「這枚憑據何時失效」這件事在裝置清單上
// 還看得到一會兒，使用者剛撤銷的裝置不會憑空消失，而是短暫顯示為「已撤銷」。
// 每一行的狀態由 Session.State 現推（撤銷優先於到期），不在庫裡多存一個 status 欄。
package session

import (
	"context"
	"errors"
	"fmt"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// ListBySubject 列舉某主體名下、尚未被清理的全部會話（含寬限期內的失效行）。
//
// 查詢範圍只由主體決定（subjectFilter），呼叫端傳進來的 Principal 已是「只有服務端
// 能構造」的受信主體，因此這裡不存在「改一個 account_id 就看到別人裝置」的通路：
// 主體是 root 就只看 root、是某帳戶就只按它的 account_id 過濾。
// 排序以建立時刻新到舊：裝置清單最上面是「剛剛登入的那臺」，符合使用者找自己的直覺。
//
// 回傳的是完整 Session 實體，秘密不在其中（库里本就只有雜湊，見 secret.go），
// 因此呼叫端可以安心把可展示欄位對映到回應，不會碰到任何憑據材料。
// 主體形態不合格（匿名、系統、自相矛盾的 root+account_id）由 Subject.validate 當場拒絕。
func (s *Store) ListBySubject(ctx context.Context, q database.Querier, subject Subject) ([]Session, error) {
	if q == nil {
		return nil, errors.New("session: 需要可用的資料庫連線或交易")
	}
	if err := subject.validate(); err != nil {
		return nil, err
	}
	clause, args := subjectFilter(subject)
	// 表名與欄名都是本套件自己拼的常量，只有值是引數：這裡沒有字串注入面。
	rows, err := q.QueryContext(ctx,
		selectSessionSQL+" WHERE "+clause+" ORDER BY created_at DESC", args...)
	if err != nil {
		return nil, fmt.Errorf("session: 列舉主體會話失敗: %w", err)
	}
	defer rows.Close()

	var out []Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("session: 遍歷主體會話失敗: %w", err)
	}
	return out, nil
}

// RevokeDeviceBySubject 在指定主體的範圍內按 device_id 撤銷一枚會話。
//
// 回傳值 (Session, 是否本次新生效, error) 覆盖三種結局：
//   - 命中且原本有效：寫入 revoked_at，回 (實體, true, nil)——這才是「撤銷發生了」。
//   - 命中但早已撤銷：冪等 no-op，回 (實體, false, nil)——重複撤銷不是錯誤。
//   - 在本主體範圍內查無此 device_id：回 (零值, false, ErrNotFound)。
//
// 第三種結局刻意對「這個 device_id 屬於別人」與「根本沒有這枚裝置」給同一個答案：
// 呼叫端拿到 ErrNotFound 就只知道「它不是你的（還活著的）裝置」，無從據此枚舉
// 別人的裝置標識。device_id 由獨立隨機 UUIDv7 產生、且带 UNIQUE 約束，猜中別人
// 那枚的概率等同盲猜一個秘密，因此把它收斂為「查無」不損失任何合法性。
//
// 讀與寫之間用 revoked_at IS NULL 兜住並發：兩個撤銷同時打同一枚時，只有先落地的
// 那個把 revoked_at 寫進去、被回報為「新生效」，另一個 RowsAffected=0，改讀現值後
// 回報「早已撤銷」。已過絕對期限但未撤銷的行仍可撤銷（寫下行事實，與 Revoke 同一口徑），
// 讓清單上的「已到期」裝置被撤銷後統一走「已撤銷」這個最終態。
func (s *Store) RevokeDeviceBySubject(ctx context.Context, q database.Querier,
	subject Subject, deviceID idgen.ID) (Session, bool, error) {
	if q == nil {
		return Session{}, false, errors.New("session: 需要可用的資料庫連線或交易")
	}
	if err := subject.validate(); err != nil {
		return Session{}, false, err
	}
	if deviceID.IsNil() {
		// 零值裝置標識不可能是任何人的有效裝置：直接按「查無」收斂，不發查詢。
		return Session{}, false, ErrNotFound
	}
	clause, base := subjectFilter(subject)
	// 先在本主體範圍內把這一行讀出來：device_id 全域唯一，但叠加主體過濾是「撤銷只能
	// 碰自己的會話」這條界線的顯式寫法，不靠 UNIQUE 約束的巧合兜底。
	sess, err := scanSession(q.QueryRowContext(ctx,
		selectSessionSQL+" WHERE device_id = ? AND "+clause,
		append([]any{deviceID.String()}, base...)...))
	if err != nil {
		return Session{}, false, err
	}
	if !sess.RevokedAt.IsZero() {
		// 命中但早已撤銷：冪等 no-op，目標狀態本就達成，不再更新時刻。
		return sess, false, nil
	}
	now := s.clock.Now()
	// WHERE 再帶 device_id：id 已是本主體讀出來的行，疊上 device_id 讓「這條 UPDATE 只會
	// 改到這一枚裝置、且此刻仍未撤銷」在寫入那一刻由資料庫自己判定，不给越權留縫。
	res, err := q.ExecContext(ctx,
		"UPDATE sessions SET revoked_at = ? WHERE id = ? AND device_id = ? AND revoked_at IS NULL",
		timeutil.ToMillis(now), sess.ID.String(), deviceID.String())
	if err != nil {
		return Session{}, false, fmt.Errorf("session: 撤銷裝置會話失敗: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Session{}, false, fmt.Errorf("session: 讀取撤銷結果失敗: %w", err)
	}
	if n == 0 {
		// 讀與寫之間被併發撤銷：改讀現值，按「早已撤銷」回報，不謊報這次是它撤的。
		cur, err := scanSession(q.QueryRowContext(ctx, selectSessionSQL+" WHERE id = ?", sess.ID.String()))
		if err != nil {
			return Session{}, false, err
		}
		return cur, false, nil
	}
	sess.RevokedAt = now
	return sess, true, nil
}
