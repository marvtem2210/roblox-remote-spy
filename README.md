# 🔍 Roblox Remote Spy

Monitor dan analyze RemoteEvent/RemoteFunction calls dari local player. GUI-based tool untuk security testing dan auditing game Roblox.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## ✨ Features

- ✅ **Hook system** - intercept FireServer & InvokeServer calls
- ✅ **Local player only** - filter calls from your client only
- ✅ **Dashboard GUI** - draggable window with real-time statistics
- ✅ **Log display** - 50 recent logs with auto-scroll, color-coded by type
- ✅ **Statistics panel** - total calls, unique remotes, call rate, session duration
- ✅ **Export to file** - save logs as formatted text file
- ✅ **Auto-save** - automatically save logs every 30 seconds
- ✅ **Call blocker** - block suspicious patterns (nil args, negative values, huge numbers)
- ✅ **Full detail** - timestamp, remote type, path, player, caller script, arguments
- ✅ **Type formatting** - Vector3, CFrame, Color3, Enum, BrickColor, UDim2, and more
- ✅ **Minimize/Maximize** - clean minimize with content hiding
- ✅ **Pause/Resume** - toggle monitoring on/off

---

## 🚀 Usage

Paste script ke executor Roblox:

```lua
loadstring(game:HttpGet("https://raw.githubusercontent.com/marvtem2210/roblox-remote-spy/main/RemoteSpy.lua"))()
```

Atau copy langsung dari [RemoteSpy.lua](RemoteSpy.lua).

---

## 📊 GUI Preview

```
┌──────────────────────────────────────────────────────┐
│ 🔍 Remote Spy v1.0                    [–] [×]        │
├──────────────────────────────────────────────────────┤
│ 📊 STATISTICS                                        │
│ Total Calls: 45  |  Unique: 8  |  Rate: 3.2/min     │
│ Session: 14m 32s  |  Blocked: 2  |  Status: ✅ ACTIVE│
├──────────────────────────────────────────────────────┤
│ [▶️ Pause]  [🗑️ Clear]  [💾 Export]  [🚫 Block: OFF] │
├──────────────────────────────────────────────────────┤
│ 📋 RECENT CALLS                                      │
│ ┌────────────────────────────────────────────────┐   │
│ │ [12:34:56] 🔵 RemoteEvent                      │   │
│ │ ReplicatedStorage.Remotes.PurchaseItem         │   │
│ │ Player: Username (123456789)                   │   │
│ │ Caller: LocalScript                            │   │
│ │ Args: itemId = 123, price = 500                │   │
│ ├────────────────────────────────────────────────┤   │
│ │ [12:34:58] 🟢 RemoteFunction                   │   │
│ │ ReplicatedStorage.Remotes.GetInventory         │   │
│ │ Player: Username (123456789)                   │   │
│ │ Caller: LocalScript                            │   │
│ │ Args: {}                                       │   │
│ └────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────┘
```

---

## 🎮 Controls

| Button | Action |
|--------|--------|
| **▶️ Pause / ⏸️ Resume** | Toggle monitoring on/off |
| **🗑️ Clear** | Clear all logs and reset statistics |
| **💾 Export** | Save logs to file (`RemoteSpy_Logs.txt`) |
| **🚫 Block** | Toggle call blocker (blocks nil, negative, huge numbers) |

---

## 📝 Requirements

- Roblox executor (KRNL, Fluxus, Synapse X, etc.)
- `writefile`/`readfile` support (optional, for export/save)
- `checkcaller` support (optional, for better filtering)

---

## 🔧 Configuration

Edit `CONFIG` table at the top of the script:

```lua
local CONFIG = {
    MAX_LOGS = 500,                -- Max logs in buffer (FIFO)
    AUTO_SAVE_INTERVAL = 30,       -- Auto-save every N seconds
    MAX_SERIALIZATION_DEPTH = 5,   -- Max table nesting depth
    MAX_ARG_DISPLAY_LENGTH = 1000, -- Truncate long arguments
    LOG_FILE_NAME = "RemoteSpy_Logs.txt",
    ENABLE_CALL_BLOCKER = false,   -- Enable call blocking
}
```

---

## 🛡️ Call Blocker Rules

When enabled, blocks calls with:
- Nil arguments
- Negative numbers (common exploit pattern)
- Numbers > 1e10 (suspiciously large values)

For `InvokeServer`, returns `{}` (empty table) instead of `nil` to prevent game crashes.

---

## 📁 File Structure

```
roblox-remote-spy/
├── RemoteSpy.lua     # Main script (989 lines)
└── README.md         # This file
```

---

## ⚠️ Important Notes

- **Only for testing YOUR OWN games** - exploiting others' games violates Roblox ToS
- All calls are client-side only (cannot see other players' calls)
- The hook intercepts after the call, not before (transparent to game logic)
- Some executors may not support `writefile`/`readfile` (falls back to console output)

---

## 📄 License

MIT - free to use, modify, and distribute.

---

**Made for Roblox security testing and game auditing**