#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""由基本來源圖產生長夜幻境後端（Go）各平台圖示與 macOS 應用程式包。

為什麼要有這個出口
==================
各平台的圖示尺寸表是硬性的，但逐張手工匯出必然漂移：改了來源圖就會漏掉某一格，
漏掉的那格不會報錯，只會在發布後以「某台裝置上圖示還是舊的」的形式出現。
本腳本把尺寸表固化成唯一出口。

來源圖（本倉庫 assets/icons/，進版本庫）
========================================
    EvernightRealmBackendRounded.png   圓角、背景透明（用於 Linux 圖示主題）
    EvernightRealmBackendSquare.png    正方形、不透明滿版（用於店鋪素材）
    EvernightRealmBackendRounded.ico   Windows 應用程式圖示（使用者提供，原樣沿用）
    EvernightRealmBackendRounded.icns  macOS 應用程式圖示（使用者提供，原樣沿用）

用法
====
    python tools/icons/generate_icons.py                    # 產生後端全部圖示
    python tools/icons/generate_icons.py --check            # 只核對，不寫入
    python tools/icons/generate_icons.py --package-macos --binary <darwin 執行檔>

邊界
====
* 只寫入圖示與其附帶檔（resource_*.syso、packaging/ 下的 .desktop 與 .app 骨架），
  不碰業務程式碼；.desktop 由人手改一次，本腳本只核對它是否仍指向正確的圖示名稱，
  不重寫文字檔，避免產生器改壞手寫檔。
* 需要 Pillow，不連網，可重複執行（同一來源圖產生位元組相同的輸出）。
* 進版本庫的分界：只有四張來源圖與指向它們的設定檔進版控；其餘全部是由來源圖
  推導出來的產物（resource_windows_*.syso、展示圖、Linux 圖示主題），一律由
  .gitignore 排除。因此乾淨 clone 或換機器後**編譯前必須先跑一次本腳本**，
  否則 Windows 執行檔不會帶圖示（連結器不會報錯，屬靜默缺失）。
  判準由 .gitignore 決定（詳見 IGNORED_OUTPUT_MARKERS 與 --check 的一致性核對）。
* 前端（Flutter 六平台與啟動畫面）的圖示由前端倉庫自己的 tools/icons/generate_icons.py
  負責，本腳本只處理這個後端倉庫。
"""

from __future__ import annotations

import argparse
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

try:
    from PIL import Image
except ImportError:  # pragma: no cover - 環境缺件時給出可執行的指示
    sys.exit("需要 Pillow：python -m pip install Pillow")

# ---------------------------------------------------------------------------
# 品牌與路徑常數
# ---------------------------------------------------------------------------

# 品牌識別：來源檔名前綴、Linux 桌面整合用的應用程式 ID、.app 的顯示名與執行檔名。
PREFIX = "EvernightRealmBackend"
APP_ID = "moe.yashi.evernightrealm.server"
DESKTOP_NAME = "EvernightRealm Server"
EXEC_NAME = "evernight-server"

# 額外推導、不進版控的展示尺寸（供文件、README、店鋪素材使用）。
DISPLAY_SIZES = (16, 32, 48, 64, 128, 256, 512, 1024)
LINUX_HICOLOR_SIZES = (16, 24, 32, 48, 64, 128, 256, 512, 1024)

RESAMPLE = Image.Resampling.LANCZOS

# 已寫入的檔案清單，供結尾輸出（含 OUTPUT= 契約）。
_written: list[Path] = []


# ---------------------------------------------------------------------------
# 通用工具
# ---------------------------------------------------------------------------


def find_repo_root(start: Path) -> Path:
    """自 start 往上找含 go.mod 的目錄，作為本後端倉庫根。"""
    for candidate in [start, *start.parents]:
        if (candidate / "go.mod").is_file():
            return candidate
    sys.exit(f"找不到後端倉庫根（沿路徑找不到 go.mod）：{start}")


def resize(im: Image.Image, size: int) -> Image.Image:
    """縮放到 size×size；先以整數倍折半再收尾，避免大幅縮小時細節崩壞。"""
    w, h = im.size
    work = im
    while w % 2 == 0 and h % 2 == 0 and w // 2 >= size and h // 2 >= size:
        w, h = w // 2, h // 2
        work = work.resize((w, h), Image.Resampling.BOX)
    if (w, h) != (size, size):
        work = work.resize((size, size), RESAMPLE)
    return work


def save_png(im: Image.Image, path: Path, opaque: bool = False) -> None:
    """寫出 PNG；opaque=True 時壓掉 alpha 圖層（商店圖示不接受透明）。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    if opaque:
        flat = Image.alpha_composite(Image.new("RGBA", im.size, (0, 0, 0, 255)),
                                     im.convert("RGBA")).convert("RGB")
        flat.save(path, format="PNG", optimize=True)
    else:
        im.convert("RGBA").save(path, format="PNG", optimize=True)
    _written.append(path)


def copy_file(src: Path, dst: Path) -> None:
    """原樣複製（用於使用者提供的 ico／icns）。"""
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)
    _written.append(dst)


# ---------------------------------------------------------------------------
# Windows 資源物件（.syso）
# ---------------------------------------------------------------------------
#
# Go 沒有提供把圖示塞進 exe 的參數，官方作法是放一個 .syso（COFF 目的檔）在套件目錄，
# 由 go build 自動連結。這裡自行產生該物件，格式與 akavel/rsrc 的輸出一致：
# 單一 .rsrc 區段，資源樹為 型別 → 資源 ID → 語言(0x409) → 資料項目，
# 資料項目的 OffsetToData 以 COFF 重定位（ADDR32NB）交給連結器填最終 RVA。
#
# 為何不使用外部工具：rsrc 需要在產生時連網抓模組，而這個 .syso 是不進版本庫的
# 本機產物，產生器離線可跑才能確保換台機器也能重建同一份東西。

FILE_HEADER_CHARACTERISTICS = 0x0104
SECTION_CHARACTERISTICS = 0x40000040
SECTION_NAME = b".rsrc\x00\x00\x00"
COFF_HEADER_SIZE = 20 + 40

# 架構 → (COFF Machine, ADDR32NB 重定位型別)
MACHINES = {
    "amd64": (0x8664, 0x0003),
    "arm64": (0xAA64, 0x0002),
    "386": (0x014C, 0x0007),
}

RT_ICON = 3
RT_GROUP_ICON = 14
LANG_NEUTRAL_ID = 0x0409


def read_ico(ico_path: Path) -> list[dict]:
    """拆開 ICO，回傳每一格的標頭欄位與影像位元組。"""
    data = ico_path.read_bytes()
    reserved, kind, count = struct.unpack_from("<HHH", data, 0)
    if reserved != 0 or kind != 1:
        sys.exit(f"不是有效的 ICO：{ico_path}")
    out = []
    for i in range(count):
        off = 6 + 16 * i
        width, height, colors, rsv, planes, bpp, size, img_off = struct.unpack_from(
            "<BBBBHHII", data, off)
        image = data[img_off:img_off + size]
        if len(image) != size:
            sys.exit(f"ICO 內容截斷：{ico_path}")
        out.append({
            "common": data[off:off + 12],  # 12 位元組共用欄位
            "width": width, "height": height, "colors": colors, "reserved": rsv,
            "planes": planes, "bpp": bpp, "bytes": size, "image": image,
        })
    return out


def build_group_icon(entries: list[dict], ids: list[int]) -> bytes:
    """組 RT_GROUP_ICON 內容：GRPICONDIR + 每格 12 位元組共用欄位 + 資源 ID。"""
    out = struct.pack("<HHH", 0, 1, len(entries))
    for entry, res_id in zip(entries, ids):
        out += entry["common"] + struct.pack("<H", res_id)
    return out


def build_resources(ico_path: Path) -> list[tuple[int, int, bytes]]:
    """把 ICO 轉成資源清單：(型別, 資源 ID, 內容)，順序即資料項目順序。

    資源 ID 的編法刻意跟 akavel/rsrc 一致（群組圖示先取 1，各格再取 2..N+1），
    這樣本函式的輸出可以與已知可用的工具逐位元組對照，便於驗證。
    """
    entries = read_ico(ico_path)
    resources: list[tuple[int, int, bytes]] = []
    group_id = 1
    icon_ids = [group_id + 1 + i for i in range(len(entries))]
    for res_id, entry in zip(icon_ids, entries):
        resources.append((RT_ICON, res_id, entry["image"]))
    resources.append((RT_GROUP_ICON, group_id, build_group_icon(entries, icon_ids)))
    # 資源樹的葉節點順序是「型別升冪、同型別依加入順序」；Python 的 sort 穩定，
    # 這裡正好讓資料項目順序與葉節點順序一致（rsrc 依賴同一前提）。
    resources.sort(key=lambda item: item[0])
    return resources


def build_rsrc_section(resources: list[tuple[int, int, bytes]]) -> tuple[bytes, list[int]]:
    """產生 .rsrc 區段內容，並回傳每個資料項目 OffsetToData 的區段內位移（重定位點）。

    三層結構的位移語意不同，錯一格就會讓 exe 的圖示整個讀不出來：
      * 資源樹節點的 OffsetToData（含子目錄與資料項目）：相對於「資源目錄起點」。
      * IMAGE_RESOURCE_DATA_ENTRY.OffsetToData：RVA，所以需要 ADDR32NB 重定位。
    """
    tree: dict[int, list[int]] = {}
    for kind, res_id, _ in resources:
        tree.setdefault(kind, []).append(res_id)
    type_ids = sorted(tree)
    index_of = {(kind, res_id): i for i, (kind, res_id, _) in enumerate(resources)}

    # 第一階段：算版面。順序必須與 walk 一致：根標頭、根項目、各型別目錄（標頭、項目、
    # 其下的資源 ID 目錄），最後才是資料項目與資料本體。
    pos = 16 + 8 * len(type_ids)
    type_dir: dict[int, int] = {}
    type_entries: dict[int, int] = {}
    id_dir: dict[tuple[int, int], int] = {}
    lang_entry: dict[tuple[int, int], int] = {}
    for kind in type_ids:
        type_dir[kind] = pos
        pos += 16
        type_entries[kind] = pos
        pos += 8 * len(tree[kind])
        for res_id in tree[kind]:
            id_dir[(kind, res_id)] = pos
            pos += 16
            lang_entry[(kind, res_id)] = pos
            pos += 8

    data_entries_start = pos
    pos += 16 * len(resources)
    blob_offset: list[int] = []
    for _, _, payload in resources:
        blob_offset.append(pos)
        pos += len(payload) + (-len(payload) % 8)  # 每個資料本體對齊 8 位元組
    raw_size = pos

    section = bytearray(raw_size)
    struct.pack_into("<IIHHHH", section, 0, 0, 0, 0, 0, 0, len(type_ids))
    for i, kind in enumerate(type_ids):
        struct.pack_into("<II", section, 16 + 8 * i, kind,
                         0x80000000 | type_dir[kind])
    for kind in type_ids:
        struct.pack_into("<IIHHHH", section, type_dir[kind], 0, 0, 0, 0, 0,
                         len(tree[kind]))
        for j, res_id in enumerate(tree[kind]):
            struct.pack_into("<II", section, type_entries[kind] + 8 * j, res_id,
                             0x80000000 | id_dir[(kind, res_id)])
        for res_id in tree[kind]:
            struct.pack_into("<IIHHHH", section, id_dir[(kind, res_id)], 0, 0, 0, 0, 0, 1)
            struct.pack_into("<II", section, lang_entry[(kind, res_id)],
                             LANG_NEUTRAL_ID,
                             data_entries_start + 16 * index_of[(kind, res_id)])

    reloc_points: list[int] = []
    for i, (_, _, payload) in enumerate(resources):
        entry_pos = data_entries_start + 16 * i
        reloc_points.append(entry_pos)
        struct.pack_into("<IIII", section, entry_pos, blob_offset[i], len(payload), 0, 0)
        start = blob_offset[i]
        section[start:start + len(payload)] = payload
    return bytes(section), reloc_points


def write_syso(ico_path: Path, arch: str, out_path: Path) -> None:
    """把 ICO 的圖示資源寫成 Go 可連結的 COFF 目的檔（.syso）。"""
    machine, reloc_type = MACHINES[arch]
    resources = build_resources(ico_path)
    section, reloc_points = build_rsrc_section(resources)

    pointer_to_relocations = COFF_HEADER_SIZE + len(section)
    pointer_to_symbols = pointer_to_relocations + 10 * len(reloc_points)
    total = pointer_to_symbols + 18 + 4  # 一個符號（18）＋ 字串表標頭（4）

    blob = bytearray()
    blob += struct.pack("<HHIIIHH", machine, 1, 0, pointer_to_symbols, 1, 0,
                        FILE_HEADER_CHARACTERISTICS)
    blob += struct.pack("<8sIIIIIIHHI", SECTION_NAME, 0, 0, len(section),
                        COFF_HEADER_SIZE, pointer_to_relocations, 0,
                        len(reloc_points), 0, SECTION_CHARACTERISTICS)
    blob += section
    for rva in reloc_points:
        blob += struct.pack("<IIH", rva, 0, reloc_type)
    blob += struct.pack("<8sIhHBB", SECTION_NAME, 0, 1, 0, 3, 0)
    blob += struct.pack("<I", 4)
    if len(blob) != total:
        sys.exit(f"內部錯誤：.syso 長度不符（{len(blob)} != {total}）")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(blob))
    _written.append(out_path)


def parse_rsrc_section(section: bytes, base_rva: int = 0) -> tuple[dict[tuple[int, int], bytes], list[int]]:
    """反向解出 .rsrc 區段：回傳 {(型別, 資源 ID): 內容} 與資料項目位移清單。

    資源樹節點的位移一律相對於資源目錄起點，故基準固定為 0；資料項目裡的
    OffsetToData 是 RVA：本函式輸出（自家產生器）尚未重定位，該值是區段內位移，
    故 base_rva=0；分析連結完成的映像檔時傳入該區段的 RVA。
    """
    blobs: dict[tuple[int, int], bytes] = {}
    entry_offsets: list[int] = []

    def walk(base: int, path: list[int]) -> None:
        named, ids = struct.unpack_from("<HH", section, base + 12)
        for i in range(named + ids):
            name_or_id, off = struct.unpack_from("<II", section, base + 16 + 8 * i)
            child = path + [name_or_id & 0xFFFF]
            if off & 0x80000000:
                walk(off & 0x7FFFFFFF, child)
                continue
            entry_offsets.append(off)
            rva, size = struct.unpack_from("<II", section, off)
            if len(child) == 3:
                start = rva - base_rva
                blobs[(child[0], child[1])] = section[start:start + size]

    walk(0, [])
    return blobs, entry_offsets


def verify_syso(path: Path, ico_path: Path) -> list[str]:
    """反向解讀 .syso：核對結構，且每一格圖示內容都必須與來源 ICO 相符。"""
    problems: list[str] = []
    data = path.read_bytes()
    machine, nsect, _, psym, nsym, _, _ = struct.unpack_from("<HHIIIHH", data, 0)
    if nsect != 1 or nsym != 1:
        problems.append(f"{path.name}: 區段數／符號數異常")
        return problems
    name, _, _, raw, praw, preloc, _, nreloc, _, _ = struct.unpack_from(
        "<8sIIIIIIHHI", data, 20)
    if name.rstrip(b"\x00") != b".rsrc":
        problems.append(f"{path.name}: 區段名不是 .rsrc")
        return problems
    section = data[praw:praw + raw]
    if psym != preloc + 10 * nreloc:
        problems.append(f"{path.name}: 符號表位移與重定位表不連續")

    reloc_rvas = []
    for i in range(nreloc):
        rva, sym, _ = struct.unpack_from("<IIH", data, preloc + 10 * i)
        reloc_rvas.append(rva)
        if sym != 0:
            problems.append(f"{path.name}: 重定位指向非 .rsrc 符號")

    blobs, entry_offsets = parse_rsrc_section(section)
    if reloc_rvas != entry_offsets:
        problems.append(f"{path.name}: 重定位點與資料項目位置不一致")

    entries = read_ico(ico_path)
    group_id = 1
    icon_ids = [group_id + 1 + i for i in range(len(entries))]
    for res_id, entry in zip(icon_ids, entries):
        if blobs.get((RT_ICON, res_id)) != entry["image"]:
            problems.append(f"{path.name}: RT_ICON {res_id} 內容與來源 ICO 不符")
    want_group = build_group_icon(entries, icon_ids)
    if blobs.get((RT_GROUP_ICON, group_id)) != want_group:
        problems.append(f"{path.name}: RT_GROUP_ICON 內容與來源 ICO 不符")
    if len(blobs) != len(entries) + 1:
        problems.append(f"{path.name}: 資源數不符（{len(blobs)}）")
    return problems


# ---------------------------------------------------------------------------
# macOS 應用程式包（僅骨架；執行檔由 --binary 帶入）
# ---------------------------------------------------------------------------

MACOS_INFO_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>CFBundleDevelopmentRegion</key>
\t<string>en</string>
\t<key>CFBundleDisplayName</key>
\t<string>{display}</string>
\t<key>CFBundleExecutable</key>
\t<string>{executable}</string>
\t<key>CFBundleIconFile</key>
\t<string>AppIcon</string>
\t<key>CFBundleIdentifier</key>
\t<string>{bundle_id}</string>
\t<key>CFBundleInfoDictionaryVersion</key>
\t<string>6.0</string>
\t<key>CFBundleName</key>
\t<string>{display}</string>
\t<key>CFBundlePackageType</key>
\t<string>APPL</string>
\t<key>CFBundleShortVersionString</key>
\t<string>{version}</string>
\t<key>CFBundleVersion</key>
\t<string>{version}</string>
\t<key>LSMinimumSystemVersion</key>
\t<string>10.15</string>
\t<key>NSHighResolutionCapable</key>
\t<true/>
</dict>
</plist>
"""


# ---------------------------------------------------------------------------
# 任務表（產生與核對共用）
# ---------------------------------------------------------------------------


def png_task(path: Path, image: Image.Image, opaque: bool = False) -> dict:
    return {"kind": "png", "path": path, "image": image, "opaque": opaque}


def syso_task(path: Path, ico: Path, arch: str) -> dict:
    return {"kind": "syso", "path": path, "ico": ico, "arch": arch}


def load_sources(repo_root: Path) -> dict:
    """載入四個來源檔；缺少任何一個就停止（不猜預設圖）。"""
    icon_dir = repo_root / "assets" / "icons"
    paths = {
        "rounded_png": icon_dir / f"{PREFIX}Rounded.png",
        "square_png": icon_dir / f"{PREFIX}Square.png",
        "ico": icon_dir / f"{PREFIX}Rounded.ico",
        "icns": icon_dir / f"{PREFIX}Rounded.icns",
    }
    missing = [str(p) for p in paths.values() if not p.is_file()]
    if missing:
        sys.exit("缺少來源圖，請先放入 assets/icons/：\n  " + "\n  ".join(missing))
    return {
        "root": repo_root,
        "prefix": PREFIX,
        "rounded": Image.open(paths["rounded_png"]).convert("RGBA"),
        "square": Image.open(paths["square_png"]).convert("RGBA"),
        "ico": paths["ico"],
        "icns": paths["icns"],
    }


# 不進版控的產物（相對片段，比對 POSIX 路徑子字串）。必須與本倉庫的 .gitignore 一致：
# 這些產物在乾淨 clone 上本來就不存在，所以核對時允許缺席，有出現才比對內容。
# --check 會用 git check-ignore 交叉核對本清單，出現偏差會直接報出來。
IGNORED_OUTPUT_MARKERS = (
    "/cmd/evernight-server/resource_windows_",  # Windows 內嵌圖示（Go 連結器吃）
    "/assets/icons/generated/",              # 多尺寸展示圖、商店圖
    "/packaging/linux/icons/",               # Linux 圖示主題（打包時安裝）
)


def is_ignored_output(path: Path) -> bool:
    """此產物是否屬於「不進版控」的那一類（離線判定：只看上面的清單）。"""
    posix = path.as_posix()
    return any(marker in posix for marker in IGNORED_OUTPUT_MARKERS)


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def git_ignored(paths: list[Path], roots: list[Path]) -> dict[Path, bool] | None:
    """用 git check-ignore 問出每個產物的忽略狀態。

    git 不裝、不在倉庫裡、或呼叫失敗時回傳 None（呼叫方改走離線清單）。
    check-ignore 預設會參考索引，所以「已被追蹤」的檔不會回報為忽略，
    正是我們要的語意：它區分的是「不進版控」而不是「符合忽略樣式」。
    """
    result: dict[Path, bool] = {path: False for path in paths}
    queried = False
    for root in roots:
        group = [p for p in paths if _is_within(p, root)]
        if not group:
            continue
        payload = b"\0".join(
            p.relative_to(root).as_posix().encode("utf-8") for p in group) + b"\0"
        try:
            # 用 -z（NUL 分隔）而不是逐行餵 stdin：Windows 上文字模式的 stdin 會把
            # \n 轉成 \r\n，git 收到帶 \r 的路徑就當成含控制字元，輸出時整條加引號
            # （"path\r"），字典查不中，於是核對永遠判定「忽略清單與 .gitignore
            # 不一致」。NUL 不受換行轉換影響，順帶也免掉引號解析與編碼問題。
            done = subprocess.run(
                ["git", "-C", str(root), "check-ignore", "-z", "--stdin"],
                input=payload, capture_output=True, check=False)
        except (OSError, ValueError):
            return None
        # 0＝有命中、1＝都沒命中，兩者都代表指令正常執行完畢。
        if done.returncode not in (0, 1):
            return None
        queried = True
        for raw in done.stdout.split(b"\0"):
            line = raw.decode("utf-8", "surrogateescape").strip()
            if line:
                result[(root / line).resolve()] = True
    return result if queried else None


def resolve_ignored(tasks: list[dict], roots: list[Path]) -> tuple[dict[Path, bool], list[str]]:
    """決定每個產物是否「不進版控」，並回傳（旗標、與 .gitignore 的偏差）。"""
    flags = {task["path"]: is_ignored_output(task["path"]) for task in tasks}
    by_git = git_ignored(list(flags), roots)
    if by_git is None:
        return flags, []
    drift: list[str] = []
    for path, flag in flags.items():
        actual = by_git.get(path, False)
        if actual != flag:
            drift.append(
                f"忽略清單與 .gitignore 不一致：{path}"
                f"（清單判定{'忽略' if flag else '需存在'}，"
                f".gitignore 判定{'忽略' if actual else '需存在'}）")
            if flag and not actual:
                # 最常見的原因：檔案還在 Git 索引裡（先前已 add），ignore 規則本身沒錯。
                drift.append("    提示：若 .gitignore 已含對應規則，通常是該檔仍在 Git 索引中，"
                             "需由使用者執行 git rm --cached 取消追蹤後才會一致。")
    return flags, drift


def display_tasks(root: Path, src: dict) -> list[dict]:
    """推導多尺寸展示圖與店鋪素材（不進版控，需要時再跑）。"""
    out_dir = root / "assets" / "icons" / "generated"
    tasks: list[dict] = []
    for size in DISPLAY_SIZES:
        tasks.append(png_task(out_dir / "png" / "rounded" / f"{size}.png",
                              resize(src["rounded"], size)))
        tasks.append(png_task(out_dir / "png" / "square" / f"{size}.png",
                              resize(src["square"], size), opaque=True))
    # 店鋪素材：Google Play 要求 512×512、無透明、不可自帶圓角；
    # App Store 要求 1024×1024、無透明、不可自帶圓角。
    tasks.append(png_task(out_dir / "store" / "play-512.png",
                          resize(src["square"], 512), opaque=True))
    tasks.append(png_task(out_dir / "store" / "appstore-1024.png",
                          resize(src["square"], 1024), opaque=True))
    return tasks


def linux_hicolor_tasks(root: Path, src: dict) -> list[dict]:
    """Linux 圖示主題（hicolor），供 .desktop 與 GTK 以應用程式 ID 取用。"""
    base = root / "packaging" / "linux" / "icons" / "hicolor"
    tasks = []
    for size in LINUX_HICOLOR_SIZES:
        tasks.append(png_task(base / f"{size}x{size}" / "apps" / f"{APP_ID}.png",
                              resize(src["rounded"], size)))
    return tasks


def backend_tasks(repo_root: Path, src: dict) -> list[dict]:
    """後端（Go）三平台圖示產物。"""
    root = src["root"]
    tasks: list[dict] = []

    # Windows：Go 以套件目錄下的 .syso 內嵌資源；檔名的 GOOS/GOARCH 後綴讓
    # 交叉編譯其他平台時不會把 PE 目的檔一起帶進去。
    # 這個 .syso 不進版庫，乾淨 clone 或換機器時由本腳本現場產生。
    pkg = root / "cmd" / "evernight-server"
    for arch in ("amd64", "arm64"):
        tasks.append(syso_task(pkg / f"resource_windows_{arch}.syso", src["ico"], arch))

    # Linux：圖示主題，供 .desktop 與檔案管理員使用。
    tasks.extend(linux_hicolor_tasks(root, src))

    tasks.extend(display_tasks(root, src))
    return tasks


# ---------------------------------------------------------------------------
# 執行與核對
# ---------------------------------------------------------------------------


def execute(tasks: list[dict]) -> None:
    for task in tasks:
        kind = task["kind"]
        if kind == "png":
            save_png(task["image"], task["path"], task["opaque"])
        elif kind == "syso":
            write_syso(task["ico"], task["arch"], task["path"])
        else:  # pragma: no cover - 任務表由本檔產生，不該出現未知型別
            sys.exit(f"未知的任務型別：{kind}")


def check(tasks: list[dict], optional: dict[Path, bool]) -> tuple[list[str], int, int]:
    """核對輸出檔，回傳（問題清單、已核對數、允許缺席而確實缺席數）。"""
    problems: list[str] = []
    verified = 0
    absent = 0
    for task in tasks:
        path = task["path"]
        kind = task["kind"]
        if not path.is_file():
            if optional.get(path, False):
                # 不進版控的產物不要求存在，才不會讓乾淨 clone 上的核對失敗。
                absent += 1
                continue
            problems.append(f"缺少檔案：{path}")
            continue
        verified += 1
        if kind == "png":
            with Image.open(path) as im:
                want = task["image"].size
                if im.size != want:
                    problems.append(f"尺寸不符：{path}（{im.size} != {want}）")
                if task["opaque"] and im.mode != "RGB":
                    problems.append(f"應為不透明卻帶有 alpha：{path}（{im.mode}）")
        elif kind == "syso":
            problems.extend(verify_syso(path, task["ico"]))
    return problems, verified, absent


def check_glue(repo_root: Path) -> list[str]:
    """核對人手改過的黏著設定檔仍指向正確的圖示名稱。"""
    checks: list[tuple[Path, list[str]]] = [
        (repo_root / "packaging/linux/evernightrealm-server.desktop", [APP_ID]),
    ]

    problems: list[str] = []
    for path, needles in checks:
        if not path.is_file():
            problems.append(f"缺少黏著設定檔：{path}")
            continue
        text = path.read_text(encoding="utf-8")
        low = text.lower()
        for needle in needles:
            if needle.lower() not in low:
                problems.append(f"{path} 未包含預期設定：{needle}")
    return problems


# ---------------------------------------------------------------------------
# macOS 應用程式包
# ---------------------------------------------------------------------------


def package_macos(repo_root: Path, binary: Path | None, out_dir: Path,
                  version: str) -> Path:
    """組出 .app 骨架（Info.plist、AppIcon.icns，可選帶入 darwin 執行檔）。

    單一執行檔在 macOS 上無法自帶圖示，只有包成 .app 才會被 Dock 與 Finder 採用，
    因此這裡產生的是「可執行的應用程式包」而不是只有圖示。
    """
    icon_dir = repo_root / "assets" / "icons"
    icns = icon_dir / f"{PREFIX}Rounded.icns"
    if not icns.is_file():
        sys.exit(f"缺少 macOS 圖示：{icns}")

    app = out_dir / f"{DESKTOP_NAME}.app"
    contents = app / "Contents"
    (contents / "MacOS").mkdir(parents=True, exist_ok=True)
    (contents / "Resources").mkdir(parents=True, exist_ok=True)

    plist = MACOS_INFO_PLIST.format(display=DESKTOP_NAME,
                                    executable=EXEC_NAME,
                                    bundle_id=APP_ID, version=version)
    (contents / "Info.plist").write_text(plist, encoding="utf-8")
    _written.append(contents / "Info.plist")

    copy_file(icns, contents / "Resources" / "AppIcon.icns")

    if binary is not None:
        if not binary.is_file():
            sys.exit(f"找不到執行檔：{binary}")
        target = contents / "MacOS" / EXEC_NAME
        copy_file(binary, target)
        os.chmod(target, 0o755)
    return app


# ---------------------------------------------------------------------------
# 命令列
# ---------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="由基本來源圖產生後端各平台圖示與 macOS 應用程式包")
    parser.add_argument("--repo", default=None,
                        help="後端倉庫根目錄（預設自本檔位置往上找 go.mod）")
    parser.add_argument("--check", action="store_true",
                        help="只核對現況，不寫入任何檔案")
    parser.add_argument("--package-macos", action="store_true",
                        help="額外組出後端 macOS 應用程式包（.app）")
    parser.add_argument("--binary", default=None,
                        help="搭配 --package-macos：要放進 .app 的 darwin 執行檔")
    parser.add_argument("--version", default="1.0.0",
                        help="macOS 應用程式包使用的版本號（預設 1.0.0）")
    args = parser.parse_args(argv)

    repo_root = (Path(args.repo).resolve() if args.repo
                 else find_repo_root(Path(__file__).resolve().parent))

    src = load_sources(repo_root)
    tasks = backend_tasks(repo_root, src)
    problems = check_glue(repo_root)

    optional, drift = resolve_ignored(tasks, [repo_root])
    present_ignored = sum(1 for path, flag in optional.items()
                          if flag and path.is_file())

    if args.check:
        found, verified, absent = check(tasks, optional)
        problems += found + drift
        if problems:
            print("[圖示核對] 發現問題：")
            for line in problems:
                print("  -", line)
            return 1
        print(f"[圖示核對] 通過：{verified} 個輸出檔符合預期"
              f"（其中 {present_ignored} 個不進版控、一併核對過），"
              f"黏著設定檔亦指向正確來源。")
        if absent:
            print(f"[圖示核對] 另有 {absent} 個產物未產生"
                  f"（含 Windows 內嵌 .syso；編譯前執行產生即可）。")
        return 0

    if drift:
        print("[圖示產生] 警告：忽略清單與 .gitignore 不一致：")
        for line in drift:
            print("  -", line)

    if problems:
        print("[圖示核對] 黏著設定檔有問題，先修正再產生：")
        for line in problems:
            print("  -", line)
        return 1

    execute(tasks)

    app_path = None
    if args.package_macos:
        binary = Path(args.binary).resolve() if args.binary else None
        app_path = package_macos(repo_root, binary,
                                 repo_root / "dist" / "macos", args.version)

    print(f"[圖示產生] 完成 {len(tasks)} 個輸出檔。")
    if app_path is not None:
        print(f"[圖示產生] macOS 應用程式包：{app_path}")
    for path in _written:
        print(f"OUTPUT={path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
