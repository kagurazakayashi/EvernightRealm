package devkit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseGitmodules(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    []SubmoduleEntry
	}{
		{
			name:    "真實格式",
			content: realGitmodules,
			want:    []SubmoduleEntry{{Name: "EvernightRealmAPP", Path: "EvernightRealmAPP"}},
		},
		{
			name: "多筆依順序回傳",
			content: `[submodule "a"]
	path = dir-a
[submodule "b"]
	path = libs/dir-b
`,
			want: []SubmoduleEntry{{Name: "a", Path: "dir-a"}, {Name: "b", Path: "libs/dir-b"}},
		},
		{
			name:    "CRLF 與註解與多餘空白",
			content: "; 註解\r\n# 註解\r\n  [submodule \"a\"]\r\n\tpath  =  dir-a \r\n branch = main\r\n",
			want:    []SubmoduleEntry{{Name: "a", Path: "dir-a"}},
		},
		{
			name:    "path 帶引號",
			content: "[submodule \"a\"]\npath = \"dir a\"\n",
			want:    []SubmoduleEntry{{Name: "a", Path: "dir a"}},
		},
		{
			name:    "缺少 path 的記錄不成立",
			content: "[submodule \"a\"]\nurl = x\n",
			want:    nil,
		},
		{
			name:    "區段外的鍵值被忽略",
			content: "path = nope\n[submodule \"a\"]\npath = ok-dir\n",
			want:    []SubmoduleEntry{{Name: "a", Path: "ok-dir"}},
		},
		{
			name:    "空檔",
			content: "",
			want:    nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseGitmodules(tc.content)
			if len(got) != len(tc.want) {
				t.Fatalf("筆數 %d，預期 %d（%#v）", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("第 %d 筆為 %#v，預期 %#v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestReadSubmodulesRejectsMissingFile(t *testing.T) {
	if _, err := ReadSubmodules(t.TempDir()); err == nil {
		t.Fatal("缺少 .gitmodules 時應回傳錯誤")
	}
}

func TestReadSubmodulesRejectsEmptyList(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, GitmodulesFile, "# 尚無子模組\n")
	if _, err := ReadSubmodules(root); err == nil {
		t.Fatal(".gitmodules 內無記錄時應回傳錯誤")
	}
}

func TestSelectSubmodule(t *testing.T) {
	single := []SubmoduleEntry{{Name: "app", Path: "frontend-app"}}
	multi := []SubmoduleEntry{{Name: "app", Path: "frontend-app"}, {Name: "docs", Path: "docs-site"}}

	t.Run("恰好一筆時不需指名", func(t *testing.T) {
		got, err := SelectSubmodule(single, "")
		if err != nil {
			t.Fatalf("不應失敗: %v", err)
		}
		if got.Name != "app" {
			t.Errorf("選到 %q", got.Name)
		}
	})

	t.Run("多筆而未指名時拒絕並列出選項", func(t *testing.T) {
		_, err := SelectSubmodule(multi, "")
		if err == nil {
			t.Fatal("多筆子模組未指名時應拒絕")
		}
		if !strings.Contains(err.Error(), "--module") {
			t.Errorf("錯誤訊息應指出可用 --module 指名: %v", err)
		}
		if !strings.Contains(err.Error(), "docs") {
			t.Errorf("錯誤訊息應列出現有記錄: %v", err)
		}
	})

	t.Run("依名稱或路徑指名", func(t *testing.T) {
		for _, wanted := range []string{"docs", "docs-site"} {
			got, err := SelectSubmodule(multi, wanted)
			if err != nil {
				t.Fatalf("以 %q 指名失敗: %v", wanted, err)
			}
			if got.Path != "docs-site" {
				t.Errorf("以 %q 指名選到 %#v", wanted, got)
			}
		}
	})

	t.Run("名稱大小寫不敏感", func(t *testing.T) {
		got, err := SelectSubmodule(multi, "APP")
		if err != nil || got.Path != "frontend-app" {
			t.Fatalf("大小寫應不敏感，實際 err=%v got=%#v", err, got)
		}
	})

	t.Run("指名對不上時不退回預設", func(t *testing.T) {
		if _, err := SelectSubmodule(single, "nope"); err == nil {
			t.Fatal("指名不存在時應拒絕，而不是拿唯一的記錄頂替")
		}
	})
}

func TestResolveRepoRootFrom(t *testing.T) {
	root, appDir := fakeRepo(t, realGitmodules)

	t.Run("自子目錄向上找到倉庫根", func(t *testing.T) {
		nested := filepath.Join(appDir, "lib", "src")
		if err := os.MkdirAll(nested, 0o755); err != nil {
			t.Fatalf("建立深層目錄失敗: %v", err)
		}
		got, err := ResolveRepoRootFrom(nested, "")
		if err != nil {
			t.Fatalf("不應失敗: %v", err)
		}
		if filepath.Clean(got) != filepath.Clean(root) {
			t.Errorf("找到 %q，預期 %q", got, root)
		}
	})

	t.Run("明指倉庫根", func(t *testing.T) {
		got, err := ResolveRepoRootFrom(t.TempDir(), root)
		if err != nil {
			t.Fatalf("不應失敗: %v", err)
		}
		if filepath.Clean(got) != filepath.Clean(root) {
			t.Errorf("得到 %q", got)
		}
	})

	t.Run("明指的目錄不存在時拒絕", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "nope")
		if _, err := ResolveRepoRootFrom(t.TempDir(), missing); err == nil {
			t.Fatal("目錄不存在時應拒絕")
		}
	})

	t.Run("明指的目錄內無 .gitmodules 時拒絕", func(t *testing.T) {
		if _, err := ResolveRepoRootFrom(t.TempDir(), appDir); err == nil {
			t.Fatal("子模組目錄不是倉庫根，應拒絕")
		}
	})

	t.Run("向上找不到時拒絕且指明起點", func(t *testing.T) {
		orphan := t.TempDir()
		_, err := ResolveRepoRootFrom(orphan, "")
		if err == nil {
			t.Fatal("找不到 .gitmodules 時應回傳錯誤")
		}
		if !strings.Contains(err.Error(), GitmodulesFile) {
			t.Errorf("錯誤訊息應點出找不到的檔案: %v", err)
		}
	})
}

func TestSubmoduleDirStaysInsideRoot(t *testing.T) {
	root, _ := fakeRepo(t, realGitmodules)

	t.Run("正常相對路徑", func(t *testing.T) {
		got, err := SubmoduleDir(root, SubmoduleEntry{Name: "app", Path: "frontend-app"})
		if err != nil {
			t.Fatalf("不應失敗: %v", err)
		}
		if filepath.Clean(got) != filepath.Join(filepath.Clean(root), "frontend-app") {
			t.Errorf("得到 %q", got)
		}
	})

	rejects := []struct {
		name string
		path string
	}{
		{name: "上跳一層", path: "../elsewhere"},
		{name: "中途上跳", path: "libs/../../elsewhere"},
		{name: "指向倉庫根", path: "."},
		{name: "空白", path: "   "},
	}
	for _, tc := range rejects {
		t.Run("拒絕 "+tc.name, func(t *testing.T) {
			if _, err := SubmoduleDir(root, SubmoduleEntry{Name: "app", Path: tc.path}); err == nil {
				t.Errorf("path=%q 應被拒絕", tc.path)
			}
		})
	}
}

func TestContainsPath(t *testing.T) {
	base := t.TempDir()
	inner := filepath.Join(base, "a", "b")
	outside := filepath.Join(filepath.Dir(base), "sibling")

	cases := []struct {
		name          string
		outer, innerP string
		want          bool
	}{
		{name: "相同目錄", outer: base, innerP: base, want: true},
		{name: "直接子孫", outer: base, innerP: inner, want: true},
		{name: "兄弟目錄", outer: base, innerP: outside, want: false},
		{name: "外層對內層反向不成立", outer: inner, innerP: base, want: false},
		{name: "尾端斜線同一結果", outer: base + string(filepath.Separator), innerP: inner, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ContainsPath(tc.outer, tc.innerP); got != tc.want {
				t.Errorf("ContainsPath(%q,%q)=%v，預期 %v", tc.outer, tc.innerP, got, tc.want)
			}
		})
	}
}

func TestRelativeTo(t *testing.T) {
	root := t.TempDir()
	if got := RelativeTo(root, filepath.Join(root, "x", "y")); got != "x/y" {
		t.Errorf("得到 %q", got)
	}
	// 算不出相對路徑時（跨磁碟機等）不得回傳空字串：摘要裡少一個路徑比給絕對路徑更難查。
	if got := RelativeTo(root, filepath.Join(root, "x", "y")); got == "" {
		t.Error("摘要路徑不可為空")
	}
}
