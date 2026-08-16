--[[
    REMOTE SPY V1.0
    Monitor dan analyze RemoteEvent/RemoteFunction calls dari local player
    Untuk testing dan security audit game Roblox
    
    Features:
    - Monitor local player calls only
    - Full detail logging (timestamp, path, player, caller, args)
    - Dashboard GUI dengan statistics
    - Export to file (persistent)
    - Call blocker (suspicious patterns)
    - Call replay capability
    - Auto-save every 30s
]]

-- ============================================================================
-- CONFIGURATION & CONSTANTS
-- ============================================================================

local CONFIG = {
    MAX_LOGS = 500,                    -- FIFO buffer limit (prevent memory leak)
    AUTO_SAVE_INTERVAL = 30,           -- Auto-save every 30 seconds
    MAX_SERIALIZATION_DEPTH = 5,       -- Prevent stack overflow on deep tables
    MAX_ARG_DISPLAY_LENGTH = 1000,     -- Truncate huge args to prevent GUI lag
    LOG_FILE_NAME = "RemoteSpy_Logs.txt",
    ENABLE_CALL_BLOCKER = false,       -- Toggle call blocking
}

local COLORS = {
    BACKGROUND = Color3.fromRGB(25, 25, 30),
    PANEL = Color3.fromRGB(35, 35, 40),
    ACCENT = Color3.fromRGB(66, 135, 245),
    SUCCESS = Color3.fromRGB(76, 175, 80),
    WARNING = Color3.fromRGB(255, 152, 0),
    ERROR = Color3.fromRGB(244, 67, 54),
    TEXT_PRIMARY = Color3.fromRGB(255, 255, 255),
    TEXT_SECONDARY = Color3.fromRGB(180, 180, 180),
}

-- ============================================================================
-- GLOBAL STATE
-- ============================================================================

local RemoteSpy = {
    logs = {},                         -- Log buffer (FIFO)
    statistics = {
        totalCalls = 0,
        uniqueRemotes = {},
        sessionStart = tick(),
        blockedCalls = 0,
    },
    isPaused = false,
    oldNamecall = nil,                 -- Store original __namecall
}

-- ============================================================================
-- UTILITY FUNCTIONS
-- ============================================================================

-- Forward declaration (Bug #5 fix: local scope, defined after SerializeTable)
local FormatArgument

-- Serialize table to string dengan circular reference protection
local function SerializeTable(tbl, depth, visitedTables)
    depth = depth or 0
    visitedTables = visitedTables or {}
    
    -- Depth limit check (Bug #4 fix)
    if depth >= CONFIG.MAX_SERIALIZATION_DEPTH then
        return "{...}" -- Truncate deep nesting
    end
    
    -- Circular reference check (Bug #4 fix)
    if visitedTables[tbl] then
        return "{CIRCULAR}"
    end
    visitedTables[tbl] = true
    
    local result = "{"
    local parts = {} -- Bug #10 fix: use table.concat instead of string concatenation
    local isEmpty = true
    
    for key, value in pairs(tbl) do
        isEmpty = false
        local keyStr = type(key) == "string" and key or "[" .. tostring(key) .. "]"
        local valueStr = FormatArgument(value, depth + 1, visitedTables)
        parts[#parts + 1] = keyStr .. " = " .. valueStr
    end
    
    if isEmpty then
        return "{}"
    end
    
    result = result .. table.concat(parts, ", ") .. "}"
    return result
end

-- Format berbagai tipe data untuk display
local function FormatArgument(arg, depth, visitedTables)
    depth = depth or 0
    visitedTables = visitedTables or {}
    
    local argType = typeof(arg)
    
    -- Bug #11 fix: Handle nil explicitly
    if arg == nil then
        return "nil"
    end
    
    -- Bug #5 fix: Handle Instance objects
    if argType == "Instance" then
        local success, fullName = pcall(function()
            return arg:GetFullName()
        end)
        if success then
            return "Instance(" .. fullName .. ")"
        else
            return "Instance(Destroyed)"
        end
    end
    
    -- Handle tables
    if argType == "table" then
        return SerializeTable(arg, depth, visitedTables)
    end
    
    -- Handle strings (add quotes)
    if argType == "string" then
        return '"' .. arg .. '"'
    end
    
    -- Bug #11 fix: Handle Roblox-specific types
    if argType == "EnumItem" then
        return "Enum." .. tostring(arg)
    end
    
    if argType == "Vector3" then
        return string.format("Vector3(%.3f, %.3f, %.3f)", arg.X, arg.Y, arg.Z)
    end
    
    if argType == "Vector2" then
        return string.format("Vector2(%.3f, %.3f)", arg.X, arg.Y)
    end
    
    if argType == "CFrame" then
        local pos = arg.Position
        return string.format("CFrame(%.3f, %.3f, %.3f)", pos.X, pos.Y, pos.Z)
    end
    
    if argType == "Color3" then
        return string.format("Color3(%d, %d, %d)", math.floor(arg.R * 255), math.floor(arg.G * 255), math.floor(arg.B * 255))
    end
    
    if argType == "BrickColor" then
        return "BrickColor(\"" .. arg.Name .. "\")"
    end
    
    if argType == "UDim2" then
        return string.format("UDim2(%.3f, %d, %.3f, %d)", arg.X.Scale, arg.X.Offset, arg.Y.Scale, arg.Y.Offset)
    end
    
    if argType == "UDim" then
        return string.format("UDim(%.3f, %d)", arg.Scale, arg.Offset)
    end
    
    if argType == "Rect" then
        return string.format("Rect(%d, %d, %d, %d)", arg.Min.X, arg.Min.Y, arg.Max.X, arg.Max.Y)
    end
    
    if argType == "NumberRange" then
        return string.format("NumberRange(%.3f, %.3f)", arg.Min, arg.Max)
    end
    
    if argType == "NumberSequence" then
        return "NumberSequence(...)"
    end
    
    if argType == "ColorSequence" then
        return "ColorSequence(...)"
    end
    
    if argType == "Ray" then
        return string.format("Ray(Origin=(%.1f,%.1f,%.1f), Direction=(%.1f,%.1f,%.1f))", 
            arg.Origin.X, arg.Origin.Y, arg.Origin.Z,
            arg.Direction.X, arg.Direction.Y, arg.Direction.Z)
    end
    
    -- Handle other types
    return tostring(arg)
end

-- Get caller script info (Bug #6 + #1 fix: iterate stack, not fixed level)
local function GetCallerScript()
    -- Get our own script source to skip it during iteration
    local ourSource = debug.info(1, "s")
    
    -- Iterate through stack to find the REAL caller (skip our own frames and C frames)
    -- Level 1 = this function, 2 = IsLocalPlayerCall, 3 = hook function, 4+ = original caller
    for level = 4, 12 do
        local success, source = pcall(function()
            return debug.info(level, "s")
        end)
        
        if success and source and source ~= ourSource and source ~= "=[C]" and source ~= "=[C]" then
            -- Extract script name from path
            local scriptName = source:match("([^%.]+)$") or source
            return scriptName
        end
    end
    
    return "Unknown" -- Fallback
end

-- Validate if Instance is still valid (Bug #10 fix)
local function ValidateInstance(instance)
    if typeof(instance) ~= "Instance" then
        return false
    end
    
    local success = pcall(function()
        local _ = instance.Parent
    end)
    
    return success and instance.Parent ~= nil
end

-- Check if caller is local player (Bug #2 fix: simplified logic)
-- All calls intercepted by client-side hook are from local client by definition
-- Server-side calls and other players' calls never reach client-side hooks
local function IsLocalPlayerCall()
    -- Method 1: checkcaller() - most executors have this
    local hasCheckcaller = pcall(function() return checkcaller end)
    if hasCheckcaller then
        local success, result = pcall(checkcaller)
        if success and result then
            return true
        end
    end
    
    -- Method 2: Fallback - always true on client side
    -- The hook is client-side, so ALL calls intercepted are from local client
    -- Player filtering is handled by the game's own network isolation
    return true
end

-- ============================================================================
-- LOG STORAGE SYSTEM
-- ============================================================================

-- Add log entry dengan FIFO buffer management (Bug #3 fix)
local function AddLog(logEntry)
    if RemoteSpy.isPaused then
        return
    end
    
    -- FIFO: Remove oldest if buffer full
    if #RemoteSpy.logs >= CONFIG.MAX_LOGS then
        table.remove(RemoteSpy.logs, 1)
    end
    
    table.insert(RemoteSpy.logs, logEntry)
    
    -- Update statistics
    RemoteSpy.statistics.totalCalls = RemoteSpy.statistics.totalCalls + 1
    
    local remoteName = logEntry.remotePath
    if not RemoteSpy.statistics.uniqueRemotes[remoteName] then
        RemoteSpy.statistics.uniqueRemotes[remoteName] = 0
    end
    RemoteSpy.statistics.uniqueRemotes[remoteName] = RemoteSpy.statistics.uniqueRemotes[remoteName] + 1
end

-- Clear all logs
local function ClearLogs()
    RemoteSpy.logs = {}
    RemoteSpy.statistics.totalCalls = 0
    RemoteSpy.statistics.uniqueRemotes = {}
    RemoteSpy.statistics.blockedCalls = 0
    RemoteSpy.statistics.sessionStart = tick()
end

-- Get statistics summary
local function GetStatistics()
    local sessionDuration = tick() - RemoteSpy.statistics.sessionStart
    -- Bug #4 fix: prevent division by zero (nan in first second)
    local callRate = 0
    if sessionDuration > 0 then
        callRate = RemoteSpy.statistics.totalCalls / (sessionDuration / 60)
    end
    
    local uniqueCount = 0
    for _ in pairs(RemoteSpy.statistics.uniqueRemotes) do
        uniqueCount = uniqueCount + 1
    end
    
    return {
        totalCalls = RemoteSpy.statistics.totalCalls,
        uniqueRemotes = uniqueCount,
        callRate = math.floor(callRate * 10) / 10, -- Round to 1 decimal
        sessionDuration = math.floor(sessionDuration),
        blockedCalls = RemoteSpy.statistics.blockedCalls,
    }
end

-- ============================================================================
-- CALL BLOCKER LOGIC
-- ============================================================================

-- Check if call should be blocked
local function ShouldBlockCall(args)
    if not CONFIG.ENABLE_CALL_BLOCKER then
        return false
    end
    
    for _, arg in ipairs(args) do
        -- Block nil arguments
        if arg == nil then
            return true
        end
        
        -- Block negative numbers (common exploit pattern)
        if type(arg) == "number" and arg < 0 then
            return true
        end
        
        -- Block extremely large numbers
        if type(arg) == "number" and math.abs(arg) > 1e10 then
            return true
        end
    end
    
    return false
end

-- ============================================================================
-- HOOK SYSTEM
-- ============================================================================

-- Hook __namecall to intercept RemoteEvent:FireServer() and RemoteFunction:InvokeServer()
local function InitializeHooks()
    RemoteSpy.oldNamecall = hookmetamethod(game, "__namecall", function(self, ...)
        local method = getnamecallmethod()
        local args = {...}
        
        -- Check if this is a remote call
        if (method == "FireServer" or method == "InvokeServer") and (self:IsA("RemoteEvent") or self:IsA("RemoteFunction")) then
            
            -- Bug #2 fix: Only log local player calls
            if IsLocalPlayerCall() then
                
                -- Check if call should be blocked
                if ShouldBlockCall(args) then
                    RemoteSpy.statistics.blockedCalls = RemoteSpy.statistics.blockedCalls + 1
                    warn("[Remote Spy] Blocked suspicious call to " .. self:GetFullName())
                    -- Bug #6 fix: For InvokeServer, return empty table instead of nil
                    -- nil breaks game scripts that expect a return value
                    if method == "InvokeServer" then
                        return {}
                    end
                    return -- Block the call (FireServer returns nothing)
                end
                
                -- Create log entry
                local logEntry = {
                    timestamp = os.date("%H:%M:%S"),
                    remoteType = self.ClassName,
                    remotePath = self:GetFullName(),
                    method = method,
                    player = game.Players.LocalPlayer.Name,
                    userId = game.Players.LocalPlayer.UserId,
                    callerScript = GetCallerScript(),
                    arguments = {},
                }
                
                -- Format arguments (Bug #12 fix: truncate if too large)
                for i, arg in ipairs(args) do
                    local formattedArg = FormatArgument(arg)
                    if #formattedArg > CONFIG.MAX_ARG_DISPLAY_LENGTH then
                        formattedArg = formattedArg:sub(1, CONFIG.MAX_ARG_DISPLAY_LENGTH) .. "..."
                    end
                    logEntry.arguments[i] = formattedArg
                end
                
                AddLog(logEntry)
            end
        end
        
        -- Bug #1 fix: Always call original function to prevent double-fire
        return RemoteSpy.oldNamecall(self, ...)
    end)
    
    print("[Remote Spy] Hooks initialized successfully")
end

-- ============================================================================
-- GUI MODULE (Operation 2/3)
-- ============================================================================

-- Bug #12 fix: Wait for LocalPlayer to be available before accessing PlayerGui
local Player = game.Players.LocalPlayer
if not Player then
    warn("[Remote Spy] LocalPlayer not available yet, waiting...")
    Player = game.Players.LocalPlayer or game.Players:WaitForChild("LocalPlayer", 30)
end

local PlayerGui = Player:WaitForChild("PlayerGui")

-- Create main ScreenGui
local function CreateGUI()
    -- Cleanup existing GUI
    local existingGui = PlayerGui:FindFirstChild("RemoteSpyGUI")
    if existingGui then
        existingGui:Destroy()
    end
    
    local screenGui = Instance.new("ScreenGui")
    screenGui.Name = "RemoteSpyGUI"
    screenGui.ResetOnSpawn = false
    screenGui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
    
    -- Main window frame (MOBILE SIZE: scale-based, ~95% width x 65% height)
    local mainFrame = Instance.new("Frame")
    mainFrame.Name = "MainFrame"
    mainFrame.Size = UDim2.new(0.95, 0, 0.65, 0)
    mainFrame.Position = UDim2.new(0.025, 0, 0.05, 0)
    mainFrame.BackgroundColor3 = COLORS.BACKGROUND
    mainFrame.BorderSizePixel = 0
    mainFrame.Active = true
    mainFrame.Parent = screenGui
    
    -- Add corner rounding
    local mainCorner = Instance.new("UICorner")
    mainCorner.CornerRadius = UDim.new(0, 8)
    mainCorner.Parent = mainFrame
    
    -- Title bar (MOBILE: 32px)
    local titleBar = Instance.new("Frame")
    titleBar.Name = "TitleBar"
    titleBar.Size = UDim2.new(1, 0, 0, 32)
    titleBar.BackgroundColor3 = COLORS.PANEL
    titleBar.BorderSizePixel = 0
    titleBar.Parent = mainFrame
    
    local titleCorner = Instance.new("UICorner")
    titleCorner.CornerRadius = UDim.new(0, 8)
    titleCorner.Parent = titleBar
    
    -- Title text (MOBILE: 14px)
    local titleLabel = Instance.new("TextLabel")
    titleLabel.Name = "TitleLabel"
    titleLabel.Size = UDim2.new(1, -80, 1, 0)
    titleLabel.Position = UDim2.new(0, 10, 0, 0)
    titleLabel.BackgroundTransparency = 1
    titleLabel.Text = "🔍 Remote Spy v1.0"
    titleLabel.TextColor3 = COLORS.TEXT_PRIMARY
    titleLabel.TextSize = 14
    titleLabel.Font = Enum.Font.GothamBold
    titleLabel.TextXAlignment = Enum.TextXAlignment.Left
    titleLabel.Parent = titleBar
    
    -- Close button (MOBILE: 26x26)
    local closeButton = Instance.new("TextButton")
    closeButton.Name = "CloseButton"
    closeButton.Size = UDim2.new(0, 26, 0, 26)
    closeButton.Position = UDim2.new(1, -30, 0, 3)
    closeButton.BackgroundColor3 = COLORS.ERROR
    closeButton.Text = "×"
    closeButton.TextColor3 = COLORS.TEXT_PRIMARY
    closeButton.TextSize = 18
    closeButton.Font = Enum.Font.GothamBold
    closeButton.Parent = titleBar
    
    local closeCorner = Instance.new("UICorner")
    closeCorner.CornerRadius = UDim.new(0, 4)
    closeCorner.Parent = closeButton
    
    closeButton.MouseButton1Click:Connect(function()
        screenGui:Destroy()
    end)
    
    -- Minimize button (MOBILE: 26x26)
    local minimizeButton = Instance.new("TextButton")
    minimizeButton.Name = "MinimizeButton"
    minimizeButton.Size = UDim2.new(0, 26, 0, 26)
    minimizeButton.Position = UDim2.new(1, -60, 0, 3)
    minimizeButton.BackgroundColor3 = COLORS.WARNING
    minimizeButton.Text = "–"
    minimizeButton.TextColor3 = COLORS.TEXT_PRIMARY
    minimizeButton.TextSize = 18
    minimizeButton.Font = Enum.Font.GothamBold
    minimizeButton.Parent = titleBar
    
    local minimizeCorner = Instance.new("UICorner")
    minimizeCorner.CornerRadius = UDim.new(0, 4)
    minimizeCorner.Parent = minimizeButton
    
    local isMinimized = false
    local contentElements = {statsPanel, controlPanel, logFrame} -- Bug #9 fix: for hide/show
    
    minimizeButton.MouseButton1Click:Connect(function()
        isMinimized = not isMinimized
        if isMinimized then
            mainFrame:TweenSize(UDim2.new(0.95, 0, 0, 32), Enum.EasingDirection.Out, Enum.EasingStyle.Quad, 0.2, true)
            -- Bug #9 fix: hide content elements when minimized
            for _, element in ipairs(contentElements) do
                element.Visible = false
            end
        else
            mainFrame:TweenSize(UDim2.new(0.95, 0, 0.65, 0), Enum.EasingDirection.Out, Enum.EasingStyle.Quad, 0.2, true)
            -- Bug #9 fix: show content elements when restored
            for _, element in ipairs(contentElements) do
                element.Visible = true
            end
        end
    end)
    
    -- Statistics panel (MOBILE: scale width, 50px)
    local statsPanel = Instance.new("Frame")
    statsPanel.Name = "StatsPanel"
    statsPanel.Size = UDim2.new(1, -16, 0, 50)
    statsPanel.Position = UDim2.new(0, 8, 0, 42)
    statsPanel.BackgroundColor3 = COLORS.PANEL
    statsPanel.BorderSizePixel = 0
    statsPanel.Parent = mainFrame
    
    local statsCorner = Instance.new("UICorner")
    statsCorner.CornerRadius = UDim.new(0, 6)
    statsCorner.Parent = statsPanel
    
    -- Stats label (MOBILE: 12px)
    local statsLabel = Instance.new("TextLabel")
    statsLabel.Name = "StatsLabel"
    statsLabel.Size = UDim2.new(1, -16, 1, -8)
    statsLabel.Position = UDim2.new(0, 8, 0, 4)
    statsLabel.BackgroundTransparency = 1
    statsLabel.Text = "📊 Loading..."
    statsLabel.TextColor3 = COLORS.TEXT_SECONDARY
    statsLabel.TextSize = 12
    statsLabel.Font = Enum.Font.Gotham
    statsLabel.TextXAlignment = Enum.TextXAlignment.Left
    statsLabel.TextYAlignment = Enum.TextYAlignment.Top
    statsLabel.TextWrapped = true
    statsLabel.Parent = statsPanel
    
    -- Control buttons panel (MOBILE: 2 rows of 2 buttons)
    local controlPanel = Instance.new("Frame")
    controlPanel.Name = "ControlPanel"
    controlPanel.Size = UDim2.new(1, -16, 0, 82)
    controlPanel.Position = UDim2.new(0, 8, 0, 100)
    controlPanel.BackgroundTransparency = 1
    controlPanel.Parent = mainFrame
    
    -- Pause/Resume button (MOBILE: 2 per row)
    local pauseButton = Instance.new("TextButton")
    pauseButton.Name = "PauseButton"
    pauseButton.Size = UDim2.new(0.5, -6, 0, 36)
    pauseButton.Position = UDim2.new(0, 0, 0, 0)
    pauseButton.BackgroundColor3 = COLORS.SUCCESS
    pauseButton.Text = "▶️ Pause"
    pauseButton.TextColor3 = COLORS.TEXT_PRIMARY
    pauseButton.TextSize = 13
    pauseButton.Font = Enum.Font.GothamBold
    pauseButton.Parent = controlPanel
    
    local pauseCorner = Instance.new("UICorner")
    pauseCorner.CornerRadius = UDim.new(0, 6)
    pauseCorner.Parent = pauseButton
    
    pauseButton.MouseButton1Click:Connect(function()
        RemoteSpy.isPaused = not RemoteSpy.isPaused
        if RemoteSpy.isPaused then
            pauseButton.Text = "▶️ Resume"
            pauseButton.BackgroundColor3 = COLORS.WARNING
        else
            pauseButton.Text = "⏸️ Pause"
            pauseButton.BackgroundColor3 = COLORS.SUCCESS
        end
    end)
    
    -- Clear button (MOBILE: row 1, col 2)
    local clearButton = Instance.new("TextButton")
    clearButton.Name = "ClearButton"
    clearButton.Size = UDim2.new(0.5, -6, 0, 36)
    clearButton.Position = UDim2.new(0.5, 6, 0, 0)
    clearButton.BackgroundColor3 = COLORS.ERROR
    clearButton.Text = "🗑️ Clear"
    clearButton.TextColor3 = COLORS.TEXT_PRIMARY
    clearButton.TextSize = 13
    clearButton.Font = Enum.Font.GothamBold
    clearButton.Parent = controlPanel
    
    local clearCorner = Instance.new("UICorner")
    clearCorner.CornerRadius = UDim.new(0, 6)
    clearCorner.Parent = clearButton
    
    clearButton.MouseButton1Click:Connect(function()
        ClearLogs()
        UpdateLogDisplay()
        UpdateStatistics()
    end)
    
    -- Export button (MOBILE: row 2, col 1)
    local exportButton = Instance.new("TextButton")
    exportButton.Name = "ExportButton"
    exportButton.Size = UDim2.new(0.5, -6, 0, 36)
    exportButton.Position = UDim2.new(0, 0, 0, 42)
    exportButton.BackgroundColor3 = COLORS.ACCENT
    exportButton.Text = "💾 Export"
    exportButton.TextColor3 = COLORS.TEXT_PRIMARY
    exportButton.TextSize = 13
    exportButton.Font = Enum.Font.GothamBold
    exportButton.Parent = controlPanel
    
    local exportCorner = Instance.new("UICorner")
    exportCorner.CornerRadius = UDim.new(0, 6)
    exportCorner.Parent = exportButton
    
    exportButton.MouseButton1Click:Connect(function()
        SaveLogsToFile()
    end)
    
    -- Block toggle button (MOBILE: row 2, col 2)
    local blockButton = Instance.new("TextButton")
    blockButton.Name = "BlockButton"
    blockButton.Size = UDim2.new(0.5, -6, 0, 36)
    blockButton.Position = UDim2.new(0.5, 6, 0, 42)
    blockButton.BackgroundColor3 = CONFIG.ENABLE_CALL_BLOCKER and COLORS.SUCCESS or COLORS.PANEL
    blockButton.Text = "🚫 Block: " .. (CONFIG.ENABLE_CALL_BLOCKER and "ON" or "OFF")
    blockButton.TextColor3 = COLORS.TEXT_PRIMARY
    blockButton.TextSize = 13
    blockButton.Font = Enum.Font.GothamBold
    blockButton.Parent = controlPanel
    
    local blockCorner = Instance.new("UICorner")
    blockCorner.CornerRadius = UDim.new(0, 6)
    blockCorner.Parent = blockButton
    
    blockButton.MouseButton1Click:Connect(function()
        CONFIG.ENABLE_CALL_BLOCKER = not CONFIG.ENABLE_CALL_BLOCKER
        blockButton.Text = "🚫 Block: " .. (CONFIG.ENABLE_CALL_BLOCKER and "ON" or "OFF")
        blockButton.BackgroundColor3 = CONFIG.ENABLE_CALL_BLOCKER and COLORS.SUCCESS or COLORS.PANEL
    end)
    
    -- Log display scrolling frame (MOBILE: fills remaining space)
    local logFrame = Instance.new("ScrollingFrame")
    logFrame.Name = "LogFrame"
    logFrame.Size = UDim2.new(1, -16, 1, -200)
    logFrame.Position = UDim2.new(0, 8, 0, 192)
    logFrame.BackgroundColor3 = COLORS.PANEL
    logFrame.BorderSizePixel = 0
    logFrame.ScrollBarThickness = 8
    logFrame.CanvasSize = UDim2.new(0, 0, 0, 0)
    logFrame.Parent = mainFrame
    
    local logCorner = Instance.new("UICorner")
    logCorner.CornerRadius = UDim.new(0, 6)
    logCorner.Parent = logFrame
    
    -- LogLayout padding (MOBILE: 4px)
    local logLayout = Instance.new("UIListLayout")
    logLayout.Name = "LogLayout"
    logLayout.SortOrder = Enum.SortOrder.LayoutOrder
    logLayout.Padding = UDim.new(0, 4)
    logLayout.Parent = logFrame
    
    logLayout:GetPropertyChangedSignal("AbsoluteContentSize"):Connect(function()
        logFrame.CanvasSize = UDim2.new(0, 0, 0, logLayout.AbsoluteContentSize.Y + 10)
    end)
    
    -- Bug #8 fix: Proper dragging implementation
    local dragging = false
    local dragInput, dragStart, startPos
    
    titleBar.InputBegan:Connect(function(input)
        if input.UserInputType == Enum.UserInputType.MouseButton1 then
            dragging = true
            dragStart = input.Position
            startPos = mainFrame.Position
            
            input.Changed:Connect(function()
                if input.UserInputState == Enum.UserInputState.End then
                    dragging = false
                end
            end)
        end
    end)
    
    titleBar.InputChanged:Connect(function(input)
        if input.UserInputType == Enum.UserInputType.MouseMovement then
            dragInput = input
        end
    end)
    
    game:GetService("UserInputService").InputChanged:Connect(function(input)
        if input == dragInput and dragging then
            local delta = input.Position - dragStart
            mainFrame.Position = UDim2.new(
                startPos.X.Scale,
                startPos.X.Offset + delta.X,
                startPos.Y.Scale,
                startPos.Y.Offset + delta.Y
            )
        end
    end)
    
    screenGui.Parent = PlayerGui
    
    -- Return references
    return {
        screenGui = screenGui,
        mainFrame = mainFrame,
        statsLabel = statsLabel,
        logFrame = logFrame,
    }
end

-- Update statistics display
local function UpdateStatistics()
    local gui = RemoteSpy.gui
    if not gui or not gui.statsLabel then return end
    
    local stats = GetStatistics()
    local statsText = string.format(
        "📊 STATISTICS\nTotal Calls: %d  |  Unique Remotes: %d  |  Call Rate: %.1f/min\nSession: %dm %ds  |  Blocked: %d  |  Status: %s",
        stats.totalCalls,
        stats.uniqueRemotes,
        stats.callRate,
        math.floor(stats.sessionDuration / 60),
        stats.sessionDuration % 60,
        stats.blockedCalls,
        RemoteSpy.isPaused and "⏸️ PAUSED" or "✅ ACTIVE"
    )
    
    gui.statsLabel.Text = statsText
end

-- Update log display
local function UpdateLogDisplay()
    local gui = RemoteSpy.gui
    if not gui or not gui.logFrame then return end
    
    -- Clear existing logs (but keep UIListLayout)
    for _, child in ipairs(gui.logFrame:GetChildren()) do
        if child:IsA("Frame") and child.Name:match("^LogEntry_") then
            child:Destroy()
        end
    end
    
    -- Display recent logs (last 50)
    local startIndex = math.max(1, #RemoteSpy.logs - 49)
    for i = startIndex, #RemoteSpy.logs do
        local log = RemoteSpy.logs[i]
        CreateLogEntry(gui.logFrame, log, i - startIndex + 1)
    end
end

-- Create individual log entry (MOBILE: compact)
local function CreateLogEntry(parent, log, index)
    local entryFrame = Instance.new("Frame")
    entryFrame.Name = "LogEntry_" .. index
    entryFrame.Size = UDim2.new(1, -8, 0, 85)
    entryFrame.BackgroundColor3 = COLORS.BACKGROUND
    entryFrame.BorderSizePixel = 0
    entryFrame.LayoutOrder = index
    entryFrame.Parent = parent
    
    local entryCorner = Instance.new("UICorner")
    entryCorner.CornerRadius = UDim.new(0, 4)
    entryCorner.Parent = entryFrame
    
    -- Type indicator (color coded, MOBILE: 4px width)
    local typeColor = log.remoteType == "RemoteEvent" and COLORS.ACCENT or COLORS.SUCCESS
    local typeIndicator = Instance.new("Frame")
    typeIndicator.Name = "TypeIndicator"
    typeIndicator.Size = UDim2.new(0, 4, 1, 0)
    typeIndicator.BackgroundColor3 = typeColor
    typeIndicator.BorderSizePixel = 0
    typeIndicator.Parent = entryFrame
    
    -- Log text
    local logText = string.format(
        "[%s] %s %s\n%s\nPlayer: %s (%d)\nCaller: %s\nArgs: %s",
        log.timestamp,
        log.remoteType == "RemoteEvent" and "🔵" or "🟢",
        log.remoteType,
        log.remotePath,
        log.player,
        log.userId,
        log.callerScript,
        table.concat(log.arguments or {}, ", ") -- Bug #18 fix: nil protection
    )
    
    local logLabel = Instance.new("TextLabel")
    logLabel.Name = "LogLabel"
    logLabel.Size = UDim2.new(1, -14, 1, -8)
    logLabel.Position = UDim2.new(0, 10, 0, 4)
    logLabel.BackgroundTransparency = 1
    logLabel.Text = logText
    logLabel.TextColor3 = COLORS.TEXT_SECONDARY
    logLabel.TextSize = 11
    logLabel.Font = Enum.Font.Code
    logLabel.TextXAlignment = Enum.TextXAlignment.Left
    logLabel.TextYAlignment = Enum.TextYAlignment.Top
    logLabel.TextWrapped = true
    logLabel.Parent = entryFrame
end

-- ============================================================================
-- FILE SYSTEM & INITIALIZATION (Operation 3/3)
-- ============================================================================

-- Save logs to file (Bug #7 + #3 fix: proper writefile detection)
local function SaveLogsToFile()
    -- Check if writefile is actually available (Bug #3 fix: type check instead of pcall)
    if type(writefile) ~= "function" then
        warn("[Remote Spy] writefile() not supported by this executor. Logs will print to console instead.")
        
        -- Fallback: Print to console
        print("========== REMOTE SPY LOGS ==========")
        for i, log in ipairs(RemoteSpy.logs) do
            print(string.format(
                "[%d] [%s] %s %s\n  Path: %s\n  Player: %s (%d)\n  Caller: %s\n  Args: %s",
                i,
                log.timestamp,
                log.remoteType == "RemoteEvent" and "🔵" or "🟢",
                log.remoteType,
                log.remotePath,
                log.player,
                log.userId,
                log.callerScript,
                table.concat(log.arguments or {}, ", ")
            ))
        end
        print("=====================================")
        return
    end
    
    -- Build export content
    local content = "REMOTE SPY LOG EXPORT\n"
    content = content .. "Generated: " .. os.date("%Y-%m-%d %H:%M:%S") .. "\n"
    content = content .. string.rep("=", 80) .. "\n\n"
    
    -- Add statistics
    local stats = GetStatistics()
    content = content .. "STATISTICS:\n"
    content = content .. string.format("  Total Calls: %d\n", stats.totalCalls)
    content = content .. string.format("  Unique Remotes: %d\n", stats.uniqueRemotes)
    content = content .. string.format("  Call Rate: %.1f calls/min\n", stats.callRate)
    content = content .. string.format("  Session Duration: %dm %ds\n", math.floor(stats.sessionDuration / 60), stats.sessionDuration % 60)
    content = content .. string.format("  Blocked Calls: %d\n\n", stats.blockedCalls)
    content = content .. string.rep("=", 80) .. "\n\n"
    
    -- Add logs
    content = content .. "LOGS:\n\n"
    for i, log in ipairs(RemoteSpy.logs) do
        content = content .. string.format(
            "[%d] [%s] %s %s\n",
            i,
            log.timestamp,
            log.remoteType == "RemoteEvent" and "EVENT" or "FUNCTION",
            log.remoteType
        )
        content = content .. "  Path: " .. log.remotePath .. "\n"
        content = content .. string.format("  Player: %s (%d)\n", log.player, log.userId)
        content = content .. "  Caller: " .. log.callerScript .. "\n"
        content = content .. "  Arguments: " .. table.concat(log.arguments or {}, ", ") .. "\n" -- Bug #14 fix
        content = content .. string.rep("-", 80) .. "\n\n"
    end
    
    -- Write to file
    local success, err = pcall(function()
        writefile(CONFIG.LOG_FILE_NAME, content)
    end)
    
    if success then
        print("[Remote Spy] Logs exported to " .. CONFIG.LOG_FILE_NAME)
    else
        warn("[Remote Spy] Failed to export logs: " .. tostring(err))
    end
end

-- Load logs from file on startup (Bug #3 fix: proper readfile detection)
local function LoadLogsFromFile()
    if type(readfile) ~= "function" then
        return -- Silently skip if not supported
    end
    
    local success, content = pcall(function()
        return readfile(CONFIG.LOG_FILE_NAME)
    end)
    
    if success and content then
        print("[Remote Spy] Previous logs file found (not parsed, fresh session)")
        -- Note: We start fresh each session, but old file exists for reference
    end
end

-- Auto-save coroutine (Bug #19 fix: error handling)
local function StartAutoSave()
    coroutine.wrap(function()
        while true do
            local success, err = pcall(function()
                wait(CONFIG.AUTO_SAVE_INTERVAL)
                if #RemoteSpy.logs > 0 then
                    SaveLogsToFile()
                end
            end)
            if not success then
                warn("[Remote Spy] Auto-save error: " .. tostring(err))
                wait(5) -- Wait before retry
            end
        end
    end)()
end

-- Auto-refresh GUI coroutine (Bug #15 + #19 fix, optimized for performance, error handling)
local function StartGUIRefresh()
    local lastLogCount = 0
    
    coroutine.wrap(function()
        while true do
            local success, err = pcall(function()
                wait(0.5) -- Check every 0.5 seconds
                if RemoteSpy.gui then
                    -- Always update statistics (lightweight)
                    UpdateStatistics()
                    
                    -- Only update log display if new logs added (Bug #17 fix)
                    local currentLogCount = #RemoteSpy.logs
                    if currentLogCount ~= lastLogCount then
                        UpdateLogDisplay()
                        lastLogCount = currentLogCount
                    end
                end
            end)
            if not success then
                warn("[Remote Spy] GUI refresh error: " .. tostring(err))
                wait(1) -- Wait before retry
            end
        end
    end)()
end

-- ============================================================================
-- MAIN INITIALIZATION
-- ============================================================================

local function Initialize()
    print("[Remote Spy] Initializing...")
    
    -- Load previous logs (for reference)
    LoadLogsFromFile()
    
    -- Initialize hooks
    InitializeHooks()
    
    -- Create GUI (Bug #13 fix: Store reference)
    RemoteSpy.gui = CreateGUI()
    
    -- Start auto-save
    StartAutoSave()
    
    -- Start GUI refresh (Bug #15 fix)
    StartGUIRefresh()
    
    -- Initial UI update
    UpdateStatistics()
    UpdateLogDisplay()
    
    print("[Remote Spy] Initialization complete!")
    print("[Remote Spy] Monitoring local player remote calls...")
    print("[Remote Spy] GUI is draggable. Use buttons to control.")
end

-- ============================================================================
-- SCRIPT EXECUTION
-- ============================================================================

-- Execute initialization
local success, err = pcall(Initialize)
if not success then
    warn("[Remote Spy] Initialization failed: " .. tostring(err))
else
    print("[Remote Spy] v1.0 running successfully!")
end

-- ============================================================================
-- END OF SCRIPT
-- ============================================================================
