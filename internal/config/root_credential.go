// root_credential.go 處理「組態檔裡那份 Root 憑據」的讀取與一次性寫入。
//
// 這一條路刻意只認組態檔本身，不經 Config 結構體，理由有兩條：
//   - Config 的值是「內建預設 → 檔案 → 環境變數 → 命令列」疊出來的，環境變數
//     （ER_SECURITY_ROOT_PASSWORD_HASH）能在記憶體裡蓋掉檔案內容。初始化要問的是
//     「這台伺服器現在有沒有 Root 憑據」，那是檔案的事實，不是記憶體的值；
//   - 以結構體重寫整份組態會丟掉註解與服務端不認識的欄位，等於把部署者手工調整過的
//     檔案重排一次。因此這裡做的是節點級編輯：只動 root_password_hash 這一個值。
//
// 寫入的不可破壞約定（由 WriteRootPasswordHash 的實作保證）：
//   - 送進來的值必須是 internal/credential 解得開的 Argon2id 編碼；這一層不收「看起來像
//     但解不開」的字串，因為這一欄寫下去就關不上了，留著壞值等於造出一個登不進去的 Root；
//   - 檔案已帶有非空值時一律拒絕，不做第二次初始化，也不覆蓋既有 Root；
//     （覆蓋既有 Root 是「已認證情況下的改密」的職責，由 UpdateRootPasswordHash 承擔，
//     見下方「覆寫」一節；兩條路各自把關，不共用一個函式的分支。）
//   - 落盤方式為同目錄臨時檔 → 寫入 → Sync → 一次改名覆蓋，失敗即清掉臨時檔，
//     原檔案在任何失敗路徑上維持位元組不變；
//   - 回傳 nil 之前一定把檔案重新讀回來逐字比對過，所以「回了成功但沒寫進去」
//     在這條路上不存在（改名之外還要求目錄 fsync，做不到時只在支援的平台嘗試）。
//
// 覆寫（UpdateRootPasswordHash）的約定與上面同源，但前提相反：它只換「已有的那一份」，
//   - 必須帶上「預期中的現有雜湊」，寫入前在互斥區內重讀檔案逐字比對——對不上就整個不動；
//     這是比較-and-set，為的是兩個並行的改密不會有一個無聲蓋掉另一個；
//   - 尚未初始化（檔案沒有非空值）時拒絕：把「建立 Root」與「更換 Root」分成兩條路，
//     各自只有一種成功形態；
//   - 同樣要求新值是可用的 Argon2id 編碼、同樣原子落盤、同樣回讀比對。
//
// 重新編碼會正規化縮排與註解位置（值、鍵序、註解文字與不認識的欄位都保留，
// 但不是逐字不動的 diff）：節點級編輯換來的是「不會把部署者的檔案重寫成結構體的形狀」，
// 代價是排版可能被調整，這件事在報告與 README 裡都照實說。
//
// 錯誤訊息與日誌一律不帶雜湊值本身；路徑可以帶——它是給本機操作者排錯用的，不是憑據。
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
)

// RootPasswordHashEnvKey 是可在執行期蓋掉組態檔 Root 雜湊的環境變數名。
//
// 匯出它是為了讓上層能明確擋下「環境變數蓋著、檔案卻被初始化」這種兩份 Root 的狀態：
// 環境變數的覆蓋能力本身保留（既有組態機制），但一次性初始化不能假裝它不存在。
const RootPasswordHashEnvKey = "ER_SECURITY_ROOT_PASSWORD_HASH"

// ErrRootAlreadyInitialized 表示組態檔已經帶有 Root 憑據雜湊。
//
// 它是「一次性」這句話的程式形態：初始化成功之後，同一條寫入通路必須永遠走到這個錯誤，
// 而不是把既有憑據換掉。要換 Root 口令屬「已認證情況下的改密」流程，是另一件事。
var ErrRootAlreadyInitialized = errors.New("config: 組態檔已帶有 Root 憑據雜湊，拒絕第二次初始化")

// ErrRootCredentialMismatch 表示覆寫時檔案現行值與「預期要換掉的舊雜湊」不一致。
//
// 它是「兩個並行的改密只能成功一個」的程式形態：比對發生在進程級互斥區內的現讀，
// 所以輸家拿到的永遠是這個錯誤而不是無聲蓋掉對手。錯誤本身不回顯任何一方的雜湊值——
// 那兩個值都是高敏感材料，差在哪裡屬呼叫端（與內部日誌）的事，不是訊息的內容。
var ErrRootCredentialMismatch = errors.New("config: 現有 Root 憑據與預期不符，覆寫中止")

// rootPasswordHashKey 是組態檔裡那個欄位的 YAML 鍵名（唯一拼寫來源）。
const rootPasswordHashKey = "root_password_hash"

// securityKey 是 Root 憑據所在的映射節點名。
const securityKey = "security"

// tempFilePattern 是原子寫入用的臨時檔名前綴。
//
// 以「.」開頭且放在同一個目錄：同一目錄才可能改名覆蓋（跨裝置改名會失敗），
// 點開頭則讓人在檔案總管裡一眼看出這不是組態檔本體。
const tempFilePattern = ".config.yaml.tmp-*"

// rootHashWriteMu 把「檢查是否已初始化」與「寫入」釘在同一個進程級互斥區裡。
//
// 跨進程的互斥不在這一層：那由資料庫的單寫入實例鎖負責（見 app 層的 init-root 子命令）。
// 這裡管的是同一進程內的多個呼叫——沒有它，兩個並行的初始化會都讀到「尚未初始化」，
// 第二個改名會安靜蓋掉第一個的成果。
var rootHashWriteMu sync.Mutex

// 檔案系統動作的注入點：生產路徑一律用標準庫實作，測試據此精確重現
// 「寫入途中失敗」的每一個階段（臨時檔建立、寫入、Sync、改名替換）。
// 覆寫只發生在同包的測試裡，生產程式碼沒有任何開關或分支讀取它們。
var (
	createTempFile = os.CreateTemp
	renamePath     = os.Rename
	removePath     = os.Remove
	openPath       = os.Open
)

// RootFileState 是「組態檔裡那份 Root 憑據」的落地狀況。
type RootFileState struct {
	// FileExists 表示組態檔是否存在。不存在時Initialized 必為 false，
	// 但兩者要能分開：「還沒建立檔案」與「檔案裡還沒填憑據」是兩句不同的話。
	FileExists bool
	// Hash 是檔案內的 Argon2id 編碼雜湊，未設定時為空字串。
	// 高敏感材料：只能用於落盤核對與憑據校驗，不得寫入日誌、審計、錯誤訊息或任何回應。
	Hash string
}

// Initialized 回報組態檔是否已帶有非空的 Root 憑據雜湊。
//
// 前後空白視同未設定：一欄寫著空字串的憑據不可能是任何合法雜湊，
// 把它當成「已初始化」會讓初始化永久關不上，而把它當成「未設定」才是事實。
func (s RootFileState) Initialized() bool { return strings.TrimSpace(s.Hash) != "" }

// ReadRootFile 只讀組態檔本身，回報 Root 憑據的落地狀況。
//
// 它不套預設值、不讀環境變數，因此可以用來判定「初始化還開不開著」。
// 組態檔不存在不是錯誤——那是首次部署的正常狀態。
//
// YAML 只解到節點層（不對任何欄位做型別轉換），這是刻意的：yaml.v3 的型別錯誤
// 訊息會把出錯欄位的值回顯出來，而節點層解析只可能回報語法問題（行號與問題描述），
// 不會把雜湊或任何其他欄位內容帶進錯誤字串。
func ReadRootFile(configPath string) (RootFileState, error) {
	data, err := os.ReadFile(configPath)
	if errors.Is(err, os.ErrNotExist) {
		return RootFileState{}, nil
	}
	if err != nil {
		return RootFileState{}, fmt.Errorf("config: 讀取組態檔 %s 失敗: %w", configPath, err)
	}

	state := RootFileState{FileExists: true}
	if strings.TrimSpace(string(data)) == "" {
		// 空檔案（或只有註解）等同「還沒有這個欄位」，不是一種初始化狀態。
		return state, nil
	}
	root, err := documentMapping(data)
	if err != nil {
		return RootFileState{}, err
	}
	_, secVal := mappingEntry(root, securityKey)
	if secVal == nil {
		return state, nil
	}
	if !isMappingOrEmpty(secVal) {
		return RootFileState{}, fmt.Errorf("config: 組態檔的 %s 節點不是映射，無法讀取 Root 憑據", securityKey)
	}
	if secVal.Kind != yaml.MappingNode {
		return state, nil
	}
	_, hashVal := mappingEntry(secVal, rootPasswordHashKey)
	if hashVal == nil {
		return state, nil
	}
	if hashVal.Kind != yaml.ScalarNode {
		return RootFileState{}, fmt.Errorf("config: 組態檔的 %s.%s 不是純量值，無法視為憑據雜湊",
			securityKey, rootPasswordHashKey)
	}
	state.Hash = hashVal.Value
	return state, nil
}

// WriteRootPasswordHash 把 Argon2id 編碼雜湊寫進組態檔，且只在該欄位尚未設定時成功。
//
// 呼叫順序就是安全順序：先擋形狀不合格的雜湊（不把明顯不是憑據的字串寫進檔），
// 再取進程級互斥，在互斥區內重新讀一次檔案做「第二次檢查」——檢查與寫入之間沒有窗口
// 給同一進程的另一個呼叫，跨進程的窗口由單寫入實例鎖關在外面。
// 最後的逐字回讀比對把「回了成功但內容沒落地」這種狀態消滅掉。
func WriteRootPasswordHash(configPath, encodedHash string) error {
	if err := validateRootHashShape(encodedHash); err != nil {
		return err
	}

	rootHashWriteMu.Lock()
	defer rootHashWriteMu.Unlock()

	state, err := ReadRootFile(configPath)
	if err != nil {
		return err
	}
	if !state.FileExists {
		return fmt.Errorf("config: 組態檔 %s 不存在，無法寫入 Root 憑據"+
			"（先以 --data-dir 執行一次 evernight-server migrate、backup 或啟動服務，讓它建立）", configPath)
	}
	if state.Initialized() {
		return ErrRootAlreadyInitialized
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("config: 讀取組態檔 %s 失敗: %w", configPath, err)
	}
	updated, err := setRootHashInYAML(data, encodedHash)
	if err != nil {
		return err
	}
	if err := writeFileAtomically(configPath, updated); err != nil {
		return err
	}

	after, err := ReadRootFile(configPath)
	if err != nil {
		return fmt.Errorf("config: 寫入後回讀組態檔失敗: %w", err)
	}
	if after.Hash != encodedHash {
		return errors.New("config: 寫入後回讀到的 Root 憑據與送入值不符，本次初始化不算成功")
	}
	return nil
}

// UpdateRootPasswordHash 以比較-and-set 覆寫組態檔中的 Root 憑據：只有檔案現行值
// 逐字等於 expectedOldHash 時，才把它換成 newHash。
//
// 這條通路存在的理由是「已認證情況下的 Root 改密」：一次性初始化（WriteRootPasswordHash）
// 之後檔案永久關上，換口令必須有一條能覆蓋既有值的路，而覆蓋的風險恰是「蓋掉別人
// 剛換好的那份」。因此這裡的把關順序與初始化同形、但檢查的對象換成現值：
//  1. 新值先過 Argon2id 嚴格解析（壞值不落盤，這條路寫下去同樣是要長期用的憑據）；
//  2. 取進程級互斥（與初始化共用 rootHashWriteMu：兩條寫入通路串行，不出現交錯的半套）；
//  3. 互斥區內重讀檔案，要求已初始化且現值與預期逐字一致，否則整個不動
//     （跨進程的窗口照舊由單寫入實例鎖擋在外面）；
//  4. 節點級覆寫那一個值（註解、鍵序、未知欄位保留），同目錄臨時檔原子替換；
//  5. 回讀逐字比對，對不上就報失敗。
//
// 呼叫端（internal/auth 的改密用例）在成功回傳後才準把新雜湊生效於記憶體：
// 回傳 nil 就意味著「檔案裡現在讀得到這份新憑據」。錯誤訊息不含任何一方的雜湊值。
func UpdateRootPasswordHash(configPath, expectedOldHash, newHash string) error {
	if strings.TrimSpace(expectedOldHash) == "" {
		return errors.New("config: 覆寫 Root 憑據必須帶上預期中的現有雜湊（尚無憑據時請走一次性初始化）")
	}
	if err := validateRootHashShape(newHash); err != nil {
		return err
	}

	rootHashWriteMu.Lock()
	defer rootHashWriteMu.Unlock()

	state, err := ReadRootFile(configPath)
	if err != nil {
		return err
	}
	if !state.FileExists {
		return fmt.Errorf("config: 組態檔 %s 不存在，無法覆寫 Root 憑據", configPath)
	}
	if !state.Initialized() {
		return fmt.Errorf("%w：組態檔目前沒有 Root 憑據；建立憑據屬一次性初始化（init-root），不是覆寫",
			ErrRootCredentialMismatch)
	}
	if strings.TrimSpace(state.Hash) != strings.TrimSpace(expectedOldHash) {
		return ErrRootCredentialMismatch
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("config: 讀取組態檔 %s 失敗: %w", configPath, err)
	}
	updated, err := replaceRootHashInYAML(data, newHash)
	if err != nil {
		return err
	}
	if err := writeFileAtomically(configPath, updated); err != nil {
		return err
	}

	after, err := ReadRootFile(configPath)
	if err != nil {
		return fmt.Errorf("config: 覆寫後回讀組態檔失敗: %w", err)
	}
	if after.Hash != newHash {
		return errors.New("config: 覆寫後回讀到的 Root 憑據與送入值不符，本次覆寫不算成功")
	}
	return nil
}

// replaceRootHashInYAML 在保留全部既有內容的前提下，把已有的 root_password_hash
// 換成新值。與 setRootHashInYAML 的分工就一句話：那個只準填空白格，這個只準換已有值；
// 鍵不存在、不是純量、security 不是映射，都是「這個檔案不處於可覆寫的形態」，報錯不動它。
func replaceRootHashInYAML(data []byte, encodedHash string) ([]byte, error) {
	if strings.TrimSpace(string(data)) == "" {
		return nil, errors.New("config: 空組態檔沒有可覆寫的 Root 憑據欄位")
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("config: 解析組態檔失敗（請檢查 YAML 語法）: %w", err)
	}
	root, err := rootNodeMapping(&doc)
	if err != nil {
		return nil, err
	}
	_, secVal := mappingEntry(root, securityKey)
	if secVal == nil || secVal.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("config: 組態檔的 %s 節點不是映射，無法覆寫 Root 憑據", securityKey)
	}
	keyIdx, hashVal := mappingEntry(secVal, rootPasswordHashKey)
	if keyIdx < 0 {
		return nil, fmt.Errorf("config: 組態檔的 %s 節點裡找不到 %s 欄位，無法覆寫", securityKey, rootPasswordHashKey)
	}
	if hashVal.Kind != yaml.ScalarNode {
		return nil, fmt.Errorf("config: 組態檔的 %s.%s 不是純量值，無法覆寫 Root 憑據",
			securityKey, rootPasswordHashKey)
	}
	// 換值不換鍵：鍵節點上的標頭註解（「由 init-root 寫入……」）屬於那一行本身，
	// 覆寫只替換值純量，註解、鍵序與其他欄位一律原樣保留。
	*hashVal = *plainHashNode(encodedHash)

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, fmt.Errorf("config: 重新編碼組態檔失敗: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("config: 結束組態檔編碼失敗: %w", err)
	}
	return buf.Bytes(), nil
}

// validateRootHashShape 擋下「根本不能當憑據用」的輸入，用的是 credential 的嚴格解析。
//
// 為什麼在存儲層也要求完整解析（而不是只比前綴）：這一欄一旦寫入就永久關上，
// 放進去一串解不開的字元等於當場造出一個登不進去的 Root，而那個狀態下初始化通路
// 還會為了不擅自放棄既有憑據而拒絕蓋掉它。寫入之前多問一次形狀，成本是零，
// 換到的是「檔案裡有值」這句話真的意味著「那個值可用」。
//
// 呼叫端（internal/rootinit）另外還有一次「用真實明文驗自己剛產生的編碼」的自我校驗，
// 兩者問的不是同一件事：形狀合格不等於對得上某個口令。
func validateRootHashShape(encodedHash string) error {
	if encodedHash == "" {
		return errors.New("config: Root 憑據雜湊不可為空")
	}
	if !strings.HasPrefix(encodedHash, argon2IDPrefix) {
		return fmt.Errorf("config: Root 憑據雜湊需為 Argon2id 編碼（%s 前綴）", argon2IDPrefix)
	}
	if err := credential.CheckEncoding(encodedHash); err != nil {
		return fmt.Errorf("config: Root 憑據雜湊不是可用的 Argon2id 編碼: %w", err)
	}
	return nil
}

// argon2IDPrefix 是 Argon2id 編碼的固定前綴（與 internal/account、Validate 認的同一形狀）。
const argon2IDPrefix = "$argon2id$"

// setRootHashInYAML 在保留全部既有內容（註解、鍵序、未知欄位）的前提下寫入這一個值。
//
// 回傳的位元組一定還能被 config.Load 讀：改動範圍只有一個純量節點，必要時多一個鍵。
func setRootHashInYAML(data []byte, encodedHash string) ([]byte, error) {
	var doc yaml.Node
	if strings.TrimSpace(string(data)) == "" {
		// 空檔案：直接從一個乾淨的文件節點開始（原有的註解已經不存在，無從保留）。
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{
			{Kind: yaml.MappingNode, Tag: "!!map"},
		}}
	} else if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("config: 解析組態檔失敗（請檢查 YAML 語法）: %w", err)
	}

	// 根節點從這裡一次取出、一路用到編碼：再解析一次會得到另一棵樹，
	// 改那棵、編這棵的寫法看起來能過測試，實際上下一次跑就會把改動丟掉。
	root, err := rootNodeMapping(&doc)
	if err != nil {
		return nil, err
	}

	secIdx, secVal := mappingEntry(root, securityKey)
	if secIdx < 0 {
		secVal = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		root.Content = append(root.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: securityKey}, secVal)
	} else if !isMappingOrEmpty(secVal) {
		return nil, fmt.Errorf("config: 組態檔的 %s 節點不是映射，無法寫入 Root 憑據", securityKey)
	} else if secVal.Kind != yaml.MappingNode {
		// 寫成 `security:`（值為空）的檔案會把這裡的 secVal 帶成 null 純量；
		// 把它轉成映射再填鑰匙，否則這份組態就永遠初始化不了。
		*secVal = yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	}

	if err := applyRootHash(secVal, encodedHash); err != nil {
		return nil, err
	}
	// 縮排固定 2 格：yaml.v3 的預設是 4 格，直接編會把整份檔案重新縮排。
	// 值與註解都還在，但「只改一個欄位」的檔案應該看起來只多了一行。
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, fmt.Errorf("config: 重新編碼組態檔失敗: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("config: 結束組態檔編碼失敗: %w", err)
	}
	return buf.Bytes(), nil
}

// applyRootHash 在 security 映射內寫入 root_password_hash，已有非空值時回
// ErrRootAlreadyInitialized（呼叫端已查過一次，這裡是寫入前的最後一道閘）。
func applyRootHash(secVal *yaml.Node, encodedHash string) error {
	keyIdx, hashVal := mappingEntry(secVal, rootPasswordHashKey)
	if keyIdx >= 0 {
		if hashVal.Kind != yaml.ScalarNode {
			return fmt.Errorf("config: 組態檔的 %s.%s 不是純量值，無法寫入 Root 憑據",
				securityKey, rootPasswordHashKey)
		}
		if strings.TrimSpace(hashVal.Value) != "" {
			return ErrRootAlreadyInitialized
		}
		*hashVal = *plainHashNode(encodedHash)
		return nil
	}

	// 鍵不存在：插在 session_ttl_hours 之後（兩者同屬 security 的日常欄位），
	// 找不到就插在映射開頭——總之不追加到 cors／headers 那種巢狀區塊後面，
	// 那會讓人以為這個鍵屬於那個區塊。
	at := 0
	if idx, _ := mappingEntry(secVal, "session_ttl_hours"); idx >= 0 {
		at = idx + 2 // Content 是鍵、值交錯：idx 是鍵，idx+1 是值，插入點在值之後。
	}
	key := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   "!!str",
		Value: rootPasswordHashKey,
		// 標頭註解會變成該鍵上方的一行：讓日後打開檔案的人知道這欄不是手工填的，
		// 也不是明文口令。這句話同時涵蓋兩條寫入通路，因為 recover-root 覆寫之後，
		// 這一欄的值已經不是 init-root 留下的那一份，而註解是跟著鍵留在那裡的。
		HeadComment: "本機 Root 命令寫入：Argon2id 編碼雜湊，不是明文口令（首次由 init-root 建立，口令遺失時由 recover-root 覆寫）。",
	}
	secVal.Content = insertNodes(secVal.Content, at, key, plainHashNode(encodedHash))
	return nil
}

// plainHashNode 產生承載雜湊的純量節點。
//
// 樣式固定為雙引號：編碼裡有 `$` 與 `,`，純量不加引號在多數情況下仍然合法，
// 但引號把「這是一整串字串」寫在檔案裡，換行或複製時不會被誤讀成兩段。
func plainHashNode(encodedHash string) *yaml.Node {
	return &yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   "!!str",
		Value: encodedHash,
		Style: yaml.DoubleQuotedStyle,
	}
}

// insertNodes 在 Content 的 at 位置依序插入節點（at 超長時附加到末尾）。
func insertNodes(content []*yaml.Node, at int, nodes ...*yaml.Node) []*yaml.Node {
	if at < 0 {
		at = 0
	}
	if at > len(content) {
		at = len(content)
	}
	out := make([]*yaml.Node, 0, len(content)+len(nodes))
	out = append(out, content[:at]...)
	out = append(out, nodes...)
	return append(out, content[at:]...)
}

// documentMapping 回傳文件的根映射節點；根節點不存在或不是映射時回錯誤。
func documentMapping(data []byte) (*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("config: 解析組態檔失敗（請檢查 YAML 語法）: %w", err)
	}
	return rootNodeMapping(&doc)
}

// rootNodeMapping 取出文件的根節點並確認它是映射。
func rootNodeMapping(doc *yaml.Node) (*yaml.Node, error) {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0] == nil {
		return nil, errors.New("config: 組態檔沒有可讀取的文件節點")
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("config: 組態檔的根節點不是映射（YAML kind=%d）", root.Kind)
	}
	return root, nil
}

// mappingEntry 回傳映射內這個鍵的 Content 索引與其值節點；找不到時索引為 -1、值為 nil。
//
// 索引以 Content 中的「鍵位置」為準（值在它下一格），呼叫端要算插入點時才不會差一格。
func mappingEntry(node *yaml.Node, key string) (int, *yaml.Node) {
	if node == nil || node.Kind != yaml.MappingNode {
		return -1, nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		k := node.Content[i]
		if k != nil && k.Kind == yaml.ScalarNode && k.Value == key {
			return i, node.Content[i+1]
		}
	}
	return -1, nil
}

// isMappingOrEmpty 回報這個值節點能否承載 Root 憑據：映射可以，
// 空值（`security:` 這種寫法）也可以——它會在寫入時被換成映射。
func isMappingOrEmpty(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.MappingNode {
		return true
	}
	return node.Kind == yaml.ScalarNode && (node.Tag == "!!null" || strings.TrimSpace(node.Value) == "")
}

// writeFileAtomically 以同目錄臨時檔完成一次可拋棄的整體替換。
//
// 順序是「寫滿 → Sync → 關檔 → 改名 → 目錄 Sync」：改名之前的任何失敗都只影響臨時檔，
// 呼叫端的組態檔維持原樣；改名成功之後才宣告成立，因此不存在半份組態。
// Sync 不是裝飾：沒有它，寫進作業系統快取的內容可能在斷電或程序被強制終止時不見，
// 而那個時候呼叫端已經把「成功」回報出去了。
func writeFileAtomically(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	file, err := createTempFile(dir, tempFilePattern)
	if err != nil {
		return fmt.Errorf("config: 在 %s 建立臨時組態檔失敗: %w", dir, err)
	}
	name := file.Name()
	renamed := false
	defer func() {
		// 已改名時重複 Close 的回傳值沒有意義（內容已在目標路徑上）；
		// 未改名時把臨時檔清掉，不留下看起來像組態檔的殘骸。
		_ = file.Close()
		if !renamed {
			_ = removePath(name)
		}
	}()

	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("config: 寫入臨時組態檔失敗: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("config: 同步臨時組態檔失敗: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("config: 關閉臨時組態檔失敗: %w", err)
	}
	if err := renamePath(name, path); err != nil {
		return fmt.Errorf("config: 以臨時檔替換 %s 失敗: %w", path, err)
	}
	renamed = true
	syncDir(dir)
	return nil
}

// syncDir 嘗試對目錄做 fsync，讓「改名」本身也盡可能落盤。
//
// 失敗一律忽略而不是回報錯誤：部分平台（含 Windows）不支援以檔案句柄同步目錄項，
// 把它當成寫入失敗會讓本來完整的組態檔被報告成壞掉——那比它要防的那個風險更糟。
// 呼叫端的最終防線是寫入後的逐字回讀比對，不是這一行。
func syncDir(dir string) {
	file, err := openPath(dir)
	if err != nil {
		return
	}
	_ = file.Sync()
	_ = file.Close()
}
