// SPDX-License-Identifier: MIT
// Main dashboard window — full sidebar + 6-page layout that mirrors the
// PowerShell SecurityMonitor.ps1 dashboard one-for-one. The Designer file
// builds the static layout; this code-behind file handles the dynamic bits:
// alert receive, settings persistence, button handlers.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;
using WhitehatSecurity.Core;

namespace WhitehatSecurity.Ui;

public sealed partial class DashboardForm : Form
{
    private static readonly System.Text.Json.JsonSerializerOptions JsonExportOptions =
        new() { WriteIndented = true };

    private readonly NotifyConfig  _config;
    private readonly Logger        _logger;
    private readonly DashboardSink _sink;
    private readonly ConsoleSink   _consoleSink;
    private readonly string        _configPath;
    /// <summary>
    /// Live MonitorHost instance — used by the Behavioural Scan page so a Scan
    /// Now click reuses the engines that already hold a baseline (instead
    /// of creating fresh ones every click, which produced spurious
    /// "every running process is suspicious" floods in v7.3.4).
    /// </summary>
    private readonly MonitorHost   _host;

    // Static layout pieces from the Designer file --------------------------
    private readonly ListView _alertsList   = new();
    private readonly Panel    _alertDetail  = new();
    private readonly Label    _alertDetailTitle = new();
    private readonly TextBox  _alertDetailBody  = new();
    private readonly Button   _btnIpLookup     = new();
    private readonly Button   _btnOpenLog      = new();
    private readonly Button   _btnRegedit      = new();
    private readonly Button   _btnBlockIp      = new();
    private readonly Button   _btnKillProcess  = new();
    private readonly Button   _btnInspectThreat = new();
    private readonly Button   _btnRemediate     = new();
    private readonly Button   _btnUndoRemediation = new();
    // Every right-click action is also a button here. The panel wraps, so
    // the set can grow and the buttons still cannot overlap or run off the
    // edge at any window size — the manual row/column arithmetic they used
    // to sit in did both.
    private readonly FlowLayoutPanel _alertActions = new();
    private readonly Button   _btnCopyRow      = new();
    private readonly Button   _btnCopyMessage  = new();
    private readonly TextBox  _alertSearch     = new();
    private readonly ComboBox _alertSeverityFilter = new();
    private readonly ComboBox _alertCategoryFilter = new();
    private readonly Button   _btnExportCsv    = new();
    private readonly Button   _btnExportJson   = new();
    private readonly Button   _btnClearAlerts  = new();
    /// <summary>
    /// Master list of every alert ever received in this dashboard session.
    /// The visible ListView is rebuilt from this whenever a filter changes,
    /// so filtering is cheap and order-preserving.
    /// </summary>
    private readonly List<Alert> _allAlerts = new();
    /// <summary>Sort state for the alerts ListView column-click handler.</summary>
    private int  _alertsSortColumn = 0;
    private bool _alertsSortAsc    = false;
    private readonly RichTextBox _consoleBox = new();
    private readonly CheckBox    _consoleAutoScroll   = new();
    private readonly Label       _consoleDroppedLabel = new();
    private readonly ListView _recentList     = new();

    // Stat card value labels — assigned by BuildStatusPage in the Designer.
    private Label _alertCountValue = null!;
    private Label _connCountValue  = null!;
    private Label _procCountValue  = null!;
    private Label _uptimeValue     = null!;

    private readonly Dictionary<string, CheckBox> _settingsCheckboxes = new();
    private readonly Dictionary<string, Panel>    _navPages           = new();
    private readonly Dictionary<string, Label>    _postureLabels      = new();
    private readonly ListView _aiResultsList = new();
    private readonly Label    _aiStatusLabel = new();
    private ComboBox? _dnsProviderCombo;
    private Button? _dnsApplyButton;
    private Label? _dnsStatusLabel;
    private Alert? _selectedAlert;
    private readonly Dictionary<Alert, AlertActionState> _alertActionStates =
        new(ReferenceEqualityComparer.Instance);

    private sealed class AlertActionState
    {
        public string? Inspection { get; set; }
        public string? Status { get; set; }
        public bool Mitigated { get; set; }
        public QuarantineRecord? Quarantine { get; set; }
        public string? ServiceRestorePayload { get; set; }
        public string? BlockedIp { get; set; }
    }

    /// <summary>
    /// Status-page refresh timer. Stored in a field so FormClosed can stop
    /// AND dispose it. Without dispose, every dashboard open/close cycle
    /// leaks one Timer + the underlying Win32 timer handle, and after ~20
    /// cycles the form gets noticeably laggy as the leaked timers fight
    /// for the UI thread.
    /// </summary>
    private System.Windows.Forms.Timer? _statusTimer;
    /// <summary>One-shot 500 ms timer that kicks the first posture refresh.</summary>
    private System.Windows.Forms.Timer? _firstPostureKick;

    public DashboardForm(
        NotifyConfig  config,
        Logger        logger,
        DashboardSink sink,
        ConsoleSink   consoleSink,
        string        configPath,
        MonitorHost   host)
    {
        _config      = config;
        _logger      = logger;
        _sink        = sink;
        _consoleSink = consoleSink;
        _configPath  = configPath;
        _host        = host;

        InitializeComponent();
        PopulateAlertsBacklog();

        _sink.AlertReceived         += OnAlertReceived;
        _consoleSink.LineAppended   += OnConsoleLineAppended;

        // Pre-fill console with whatever was already buffered
        foreach (var line in _consoleSink.Snapshot())
            AppendConsoleLine(line);

        FormClosed += (_, _) =>
        {
            _sink.AlertReceived       -= OnAlertReceived;
            _consoleSink.LineAppended -= OnConsoleLineAppended;
            try { _aiScanCts?.Cancel(); } catch { }
            _aiScanCts?.Dispose();
            _aiScanCts = null;
            _alertContextMenu?.Dispose();
            _alertContextMenu = null;
        };

        // Periodic refresher for the Status page. Two separate cadences:
        //
        //   * uptime + counts on every 2 s tick (cheap, all in-process)
        //   * posture WMI queries on a background Task every 5th tick
        //     (~10 s) so the eight WMI calls never block the UI thread.
        //
        // The first posture refresh kicks off ~500 ms after the dashboard
        // appears (still on a background thread) so the dots populate
        // shortly after open without blocking the form constructor.
        _statusTimer = new System.Windows.Forms.Timer { Interval = 2000 };
        int postureTickCounter = 0;
        _statusTimer.Tick += (_, _) =>
        {
            RefreshStatusPage();
            postureTickCounter++;
            if (postureTickCounter % 5 == 0)
                BeginRefreshPostureIndicators();
        };
        _statusTimer.Start();

        // First posture refresh — fires after ~500 ms on a background
        // thread so the dashboard appears immediately and the dots populate
        // on next paint instead of blocking the form constructor on 8 WMI
        // queries (each ~200-500 ms = ~3-4 s of total UI freeze in v7.3.0).
        _firstPostureKick = new System.Windows.Forms.Timer { Interval = 500 };
        _firstPostureKick.Tick += (_, _) =>
        {
            _firstPostureKick?.Stop();
            _firstPostureKick?.Dispose();
            _firstPostureKick = null;
            BeginRefreshPostureIndicators();
        };
        _firstPostureKick.Start();

        // Final cleanup — stop AND dispose both timers so the form releases
        // every Win32 timer handle on close. Stop alone leaves the timer
        // queued in the WinForms message pump which leaks across open/close
        // cycles.
        FormClosed += (_, _) =>
        {
            _statusTimer?.Stop();
            _statusTimer?.Dispose();
            _statusTimer = null;
            _firstPostureKick?.Stop();
            _firstPostureKick?.Dispose();
            _firstPostureKick = null;
        };
    }

    /// <summary>
    /// Posture is being refreshed by a background Task — used to coalesce
    /// concurrent timer ticks so we never have two WMI scans racing.
    /// </summary>
    private int _postureRefreshing = 0;

    /// <summary>
    /// Kicks off the eight posture queries on a background Task and posts
    /// the results back via BeginInvoke. Idempotent — concurrent calls
    /// while a refresh is in flight are no-ops.
    /// </summary>
    private void BeginRefreshPostureIndicators()
    {
        if (IsDisposed) return;
        if (System.Threading.Interlocked.CompareExchange(ref _postureRefreshing, 1, 0) != 0)
            return;

        _ = System.Threading.Tasks.Task.Run(async () =>
        {
            // Run probes independently. One slow WMI provider used to hold
            // the entire row at "Unknown" because all eight calls ran
            // sequentially and the UI was updated only after the last call.
            var probes = new (string Key, Func<PostureState> Probe)[]
            {
                ("Defender",   SecurityPosture.Defender),
                ("Firewall",   SecurityPosture.Firewall),
                ("UAC",        SecurityPosture.UAC),
                ("RDP",        SecurityPosture.RdpOff),
                ("SecureBoot", SecurityPosture.SecureBoot),
                ("TPM",        SecurityPosture.Tpm),
                ("HVCI",       SecurityPosture.Hvci),
                ("BitLocker",  SecurityPosture.BitLocker),
            };
            var tasks = probes
                .Select(probe => System.Threading.Tasks.Task.Run(probe.Probe))
                .ToArray();

            try
            {
                var allProbes = System.Threading.Tasks.Task.WhenAll(tasks);
                await System.Threading.Tasks.Task.WhenAny(
                    allProbes,
                    System.Threading.Tasks.Task.Delay(TimeSpan.FromSeconds(5)))
                    .ConfigureAwait(false);

                // Publish every completed result after at most five seconds.
                // Incomplete probes remain Unknown; fast registry/service
                // checks are never held hostage by a slow WMI namespace.
                PostSnapshot(probes, tasks);

                // Keep the coalescing flag set until stragglers finish so a
                // permanently slow WMI provider cannot create an unbounded
                // queue of duplicate probes. If they do finish, publish the
                // complete snapshot immediately.
                if (!allProbes.IsCompleted)
                {
                    await allProbes.ConfigureAwait(false);
                    PostSnapshot(probes, tasks);
                }
            }
            catch
            {
                // form closing — drop on the floor
            }
            finally
            {
                System.Threading.Interlocked.Exchange(ref _postureRefreshing, 0);
            }
        });
    }

    private void PostSnapshot(
        IReadOnlyList<(string Key, Func<PostureState> Probe)> probes,
        IReadOnlyList<System.Threading.Tasks.Task<PostureState>> tasks)
    {
        try
        {
            if (IsDisposed) return;
            var snapshot = probes.Select((probe, index) =>
                (probe.Key,
                 tasks[index].Status == System.Threading.Tasks.TaskStatus.RanToCompletion
                    ? tasks[index].Result
                    : PostureState.Unknown)).ToArray();
            BeginInvoke(new Action(() =>
            {
                if (IsDisposed) return;
                foreach (var (key, state) in snapshot)
                    SetPosture(key, state);
            }));
        }
        catch
        {
            // The form can close between the IsDisposed check and BeginInvoke.
        }
    }

    private void SetPosture(string key, PostureState state)
    {
        if (!_postureLabels.TryGetValue(key, out var lbl) || lbl.IsDisposed) return;
        lbl.ForeColor = state switch
        {
            PostureState.Good => Theme.PostureGood,
            PostureState.Bad  => Theme.PostureBad,
            PostureState.NA   => Theme.PostureNa,
            _                 => Theme.PostureNa,
        };
        var stateText = state switch
        {
            PostureState.Good when key == "RDP" => "Off",
            PostureState.Bad when key == "RDP"  => "On",
            PostureState.Good                   => "On",
            PostureState.Bad                    => "Off",
            _                                   => "Unknown",
        };
        lbl.Text = $"● {key}: {stateText}";
        lbl.AccessibleName = $"{key}: {stateText}";
    }

    // -----------------------------------------------------------------------
    //  Alerts page wiring
    // -----------------------------------------------------------------------

    private void PopulateAlertsBacklog()
    {
        // _sink.All already returns a snapshot under DashboardSink's
        // internal lock, so we can enumerate it directly without taking
        // an external lock on the sink.
        foreach (var a in _sink.All) AppendAlertRow(a);
    }

    /// <summary>
    /// Returns true if the alert passes the current Search/Severity/Category
    /// filter. Used by both the live append path and the full rebuild after
    /// the user changes a filter.
    /// </summary>
    private bool MatchesAlertFilters(Alert a)
    {
        var sev = _alertSeverityFilter?.SelectedItem?.ToString() ?? "All";
        if (sev != "All" && !string.Equals(sev, a.Severity.ToString(), StringComparison.OrdinalIgnoreCase))
            return false;

        var cat = _alertCategoryFilter?.SelectedItem?.ToString() ?? "All";
        if (cat != "All" && !string.Equals(cat, a.Category, StringComparison.OrdinalIgnoreCase))
            return false;

        var search = _alertSearch?.Text;
        if (!string.IsNullOrWhiteSpace(search))
        {
            if ((a.Title?.IndexOf(search, StringComparison.OrdinalIgnoreCase) ?? -1) < 0
             && (a.Message?.IndexOf(search, StringComparison.OrdinalIgnoreCase) ?? -1) < 0
             && (a.Category?.IndexOf(search, StringComparison.OrdinalIgnoreCase) ?? -1) < 0)
                return false;
        }
        return true;
    }

    /// <summary>
    /// Tear down the visible ListView and rebuild it from `_allAlerts`
    /// honoring the current filter state. Cheap because the ListView only
    /// holds at most 1000 items.
    /// </summary>
    private void RefilterAlertsList()
    {
        if (_alertsList is null || _alertsList.IsDisposed) return;
        _alertsList.BeginUpdate();
        try
        {
            _alertsList.Items.Clear();
            // Newest first
            for (int i = _allAlerts.Count - 1; i >= 0; i--)
            {
                var a = _allAlerts[i];
                if (MatchesAlertFilters(a))
                    _alertsList.Items.Add(MakeAlertItem(a));
            }
        }
        finally { _alertsList.EndUpdate(); }
    }

    private ListViewItem MakeAlertItem(Alert a)
    {
        var item = new ListViewItem(a.Timestamp.ToString("HH:mm:ss"));
        item.SubItems.Add(a.Severity.ToString().ToUpperInvariant());
        item.SubItems.Add(a.Category);
        item.SubItems.Add(
            _alertActionStates.TryGetValue(a, out var actionState)
                && actionState.Mitigated
                ? $"[MITIGATED] {a.Title}"
                : a.Title);
        item.SubItems.Add(a.Message);
        item.ForeColor = Theme.SeverityColor(a.Severity);
        item.Tag = a;
        return item;
    }

    private void OnAlertSearchChanged(object? sender, EventArgs e)  => RefilterAlertsList();
    private void OnAlertFilterChanged(object? sender, EventArgs e)  => RefilterAlertsList();

    /// <summary>
    /// Column-click sort. First click ascending, second click descending,
    /// keeps the previously-selected column on subsequent clicks.
    /// </summary>
    private void OnAlertColumnClick(object? sender, ColumnClickEventArgs e)
    {
        if (e.Column == _alertsSortColumn)
            _alertsSortAsc = !_alertsSortAsc;
        else
        {
            _alertsSortColumn = e.Column;
            _alertsSortAsc = true;
        }
        var items = _alertsList.Items.Cast<ListViewItem>().ToList();
        int sortCol = _alertsSortColumn;
        items.Sort((x, y) =>
        {
            // Bounds check — if either row has fewer subitems than the
            // requested column, treat its value as empty rather than
            // throwing IndexOutOfRangeException. Without this, clicking
            // a header before any rows are populated could crash the
            // dashboard the first time a user changes sort.
            string xs = sortCol < x.SubItems.Count ? x.SubItems[sortCol].Text : "";
            string ys = sortCol < y.SubItems.Count ? y.SubItems[sortCol].Text : "";
            int cmp = string.Compare(xs, ys, StringComparison.OrdinalIgnoreCase);
            return _alertsSortAsc ? cmp : -cmp;
        });
        _alertsList.BeginUpdate();
        try
        {
            _alertsList.Items.Clear();
            foreach (var it in items) _alertsList.Items.Add(it);
        }
        finally { _alertsList.EndUpdate(); }
    }

    private void OnExportCsvClick(object? sender, EventArgs e)
    {
        try
        {
            using var dlg = new SaveFileDialog
            {
                Filter   = "CSV (*.csv)|*.csv|All files (*.*)|*.*",
                FileName = $"WhitehatSecurity_Alerts_{DateTime.Now:yyyyMMdd_HHmmss}.csv",
            };
            if (dlg.ShowDialog() != DialogResult.OK) return;
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("Timestamp,Severity,Category,Title,Message,RemoteIp,RemotePort,ProcessName,ProcessId,Path,ResponseStatus");
            foreach (var a in _allAlerts)
            {
                if (!MatchesAlertFilters(a)) continue;
                sb.Append(CsvField(a.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"))).Append(',');
                sb.Append(CsvField(a.Severity.ToString())).Append(',');
                sb.Append(CsvField(a.Category)).Append(',');
                sb.Append(CsvField(a.Title)).Append(',');
                sb.Append(CsvField(a.Message)).Append(',');
                sb.Append(CsvField(a.RemoteIp ?? "")).Append(',');
                sb.Append(CsvField(a.RemotePort?.ToString() ?? "")).Append(',');
                sb.Append(CsvField(a.ProcessName ?? "")).Append(',');
                sb.Append(CsvField(a.ProcessId?.ToString() ?? "")).Append(',');
                sb.Append(CsvField(a.Path ?? "")).Append(',');
                sb.Append(CsvField(
                    _alertActionStates.TryGetValue(a, out var state)
                        ? state.Status ?? ""
                        : "")).AppendLine();
            }
            File.WriteAllText(dlg.FileName, sb.ToString());
        }
        catch (Exception ex) { _logger.Error($"Export CSV: {ex.Message}"); }
    }

    private static string CsvField(string s)
        => CsvSafety.Escape(s);

    private void OnClearAlertsClick(object? sender, EventArgs e)
    {
        if (_allAlerts.Count == 0) return;
        var ans = MessageBox.Show(
            $"Clear all {_allAlerts.Count} alerts from the dashboard?\n\n" +
            "This only empties the in-memory list — the daily alert log on\n" +
            "disk is not touched.",
            "Clear All Alerts",
            MessageBoxButtons.YesNo, MessageBoxIcon.Question);
        if (ans != DialogResult.Yes) return;

        _allAlerts.Clear();
        _alertActionStates.Clear();
        _sink.Clear();
        _alertsList.BeginUpdate();
        try { _alertsList.Items.Clear(); }
        finally { _alertsList.EndUpdate(); }
        _recentList.Items.Clear();
        ClearAlertDetail();
    }

    private void OnAlertContextMenuOpening(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        // Hide every action item, then re-show the ones that apply to the
        // currently-selected alert. Cancel the menu entirely if nothing is
        // selected so the user doesn't see an empty popup.
        if (_alertsList.SelectedItems.Count == 0 || _alertsList.SelectedItems[0].Tag is not Alert a)
        {
            e.Cancel = true;
            return;
        }
        if (_alertContextMenu is null) { e.Cancel = true; return; }
        _ctxBlockIp.Visible    = a.RemoteIp is not null
            && GetAlertActionState(a).BlockedIp is null;
        _ctxIpLookup.Visible   = a.RemoteIp is not null;
        _ctxKill.Visible       = a.ProcessId is int pid && pid > 0;
        var filePath = ThreatPath.Normalize(a.Path);
        _ctxOpenLog.Visible    =
            filePath is not null && File.Exists(filePath);
        _ctxRegedit.Visible    = HasRegistryLocation(a);
        _ctxInspect.Visible    = CanInspect(a);
        _ctxRemediate.Visible  = CanRemediate(a);
        _ctxRemediate.Text     = RemediationButtonText(a);
    }

    private void OnAlertCopyRowClick(object? sender, EventArgs e)
    {
        if (_alertsList.SelectedItems.Count == 0) return;
        var item = _alertsList.SelectedItems[0];
        var sb = new System.Text.StringBuilder();
        for (int i = 0; i < item.SubItems.Count; i++)
        {
            if (i > 0) sb.Append('\t');
            sb.Append(item.SubItems[i].Text);
        }
        try { Clipboard.SetText(sb.ToString()); } catch { }
    }

    private void OnAlertCopyMessageClick(object? sender, EventArgs e)
    {
        if (_alertsList.SelectedItems.Count == 0) return;
        if (_alertsList.SelectedItems[0].Tag is Alert a)
        {
            try { Clipboard.SetText(a.Message ?? ""); } catch { }
        }
    }

    // Right-click context menu controls — built in the Designer file.
    private ContextMenuStrip? _alertContextMenu;
    private ToolStripMenuItem _ctxCopyRow     = new() { Text = "Copy row" };
    private ToolStripMenuItem _ctxCopyMessage = new() { Text = "Copy message" };
    private ToolStripMenuItem _ctxIpLookup    = new() { Text = "IP lookup" };
    private ToolStripMenuItem _ctxBlockIp     = new() { Text = "Block IP" };
    private ToolStripMenuItem _ctxKill        = new() { Text = "Kill process" };
    private ToolStripMenuItem _ctxOpenLog     = new() { Text = "Show file in Explorer" };
    private ToolStripMenuItem _ctxRegedit     = new() { Text = "Open in regedit" };
    private ToolStripMenuItem _ctxInspect     = new() { Text = "Inspect finding" };
    private ToolStripMenuItem _ctxRemediate   = new() { Text = "Remediate finding" };

    private void OnExportJsonClick(object? sender, EventArgs e)
    {
        try
        {
            using var dlg = new SaveFileDialog
            {
                Filter   = "JSON (*.json)|*.json|All files (*.*)|*.*",
                FileName = $"WhitehatSecurity_Alerts_{DateTime.Now:yyyyMMdd_HHmmss}.json",
            };
            if (dlg.ShowDialog() != DialogResult.OK) return;
            var rows = _allAlerts.Where(MatchesAlertFilters).Select(a => new
            {
                a.Timestamp, Severity = a.Severity.ToString(), a.Category,
                a.Title, a.Message, a.RemoteIp, a.RemotePort,
                a.ProcessName, a.ProcessId, a.Path,
                ResponseStatus =
                    _alertActionStates.TryGetValue(a, out var state)
                        ? state.Status
                        : null,
            });
            var json = System.Text.Json.JsonSerializer.Serialize(rows,
                JsonExportOptions);
            File.WriteAllText(dlg.FileName, json);
        }
        catch (Exception ex) { _logger.Error($"Export JSON: {ex.Message}"); }
    }

    /// <summary>
    /// Cancellation source for the in-flight AI scan, if any. Stored on
    /// the form so the Cancel button can fire it from the UI thread.
    /// </summary>
    private System.Threading.CancellationTokenSource? _aiScanCts;

    /// <summary>
    /// Behavioural Scan "Scan Now" button. Runs the three on-demand engines via
    /// MonitorHost.RunOneShotAsync against the LIVE engine instances that
    /// already hold a baseline — this avoids the v7.3.4 bug where every
    /// click recreated MemoryScannerEngine without a baseline and flooded
    /// the dashboard with one alert per running RWX-using process.
    /// </summary>
    private async void OnAiScanClick(object? sender, EventArgs e)
    {
        // If a scan is already running, the click acts as Cancel.
        if (_aiScanCts is not null)
        {
            try { _aiScanCts.Cancel(); } catch { }
            return;
        }

        _aiResultsList.Items.Clear();
        _aiStatusLabel.Text      = "Scanning...";
        _aiStatusLabel.ForeColor = Theme.Orange;

        _aiScanCts = new System.Threading.CancellationTokenSource();
        var ct     = _aiScanCts.Token;

        try
        {
            // Reuse the live MonitorHost engines (HiddenProcess, Memory,
            // BYOVD) so the scan honours each engine's baseline.
            var results = await _host.RunOneShotAsync(
                new[] { "HiddenProcess", "Memory", "BYOVD" }, ct);

            if (ct.IsCancellationRequested)
            {
                _aiStatusLabel.Text      = "Scan cancelled.";
                _aiStatusLabel.ForeColor = Theme.TextDim;
                return;
            }

            foreach (var a in results)
            {
                var item = new ListViewItem(a.Category);
                item.SubItems.Add(a.Severity.ToString().ToUpperInvariant());
                item.SubItems.Add(a.Title);
                item.SubItems.Add(a.Message);
                item.ForeColor = Theme.SeverityColor(a.Severity);
                _aiResultsList.Items.Add(item);
            }

            _aiStatusLabel.Text = results.Count == 0
                ? "Scan complete: 0 findings."
                : $"Scan complete: {results.Count} findings.";
            _aiStatusLabel.ForeColor = results.Count == 0 ? Theme.Green : Theme.Red;
        }
        catch (OperationCanceledException)
        {
            _aiStatusLabel.Text      = "Scan cancelled.";
            _aiStatusLabel.ForeColor = Theme.TextDim;
        }
        catch (Exception ex)
        {
            _logger.Error($"AI scan failed: {ex.Message}");
            _aiStatusLabel.Text      = $"Scan failed: {ex.Message}";
            _aiStatusLabel.ForeColor = Theme.Red;
        }
        finally
        {
            try { _aiScanCts?.Dispose(); } catch { }
            _aiScanCts = null;
        }
    }

    private void OnAlertReceived(Alert alert)
    {
        if (IsDisposed) return;
        if (InvokeRequired)
        {
            try { BeginInvoke(new Action<Alert>(OnAlertReceived), alert); }
            catch { /* form disposing */ }
            return;
        }
        AppendAlertRow(alert);
        RefreshStatusPage();
    }

    private void AppendAlertRow(Alert a)
    {
        // Master list keeps everything; the visible list is filter-driven.
        _allAlerts.Add(a);
        while (_allAlerts.Count > 5000)
        {
            var removed = _allAlerts[0];
            _allAlerts.RemoveAt(0);
            _alertActionStates.Remove(removed);
        }

        // Live insert into the visible list only if the current filters allow.
        if (MatchesAlertFilters(a))
        {
            var inserted = MakeAlertItem(a);
            _alertsList.Items.Insert(0, inserted);
            while (_alertsList.Items.Count > 1000)
                _alertsList.Items.RemoveAt(_alertsList.Items.Count - 1);
            if (_navPages.TryGetValue("Alerts", out var alertsPage)
                && alertsPage.Visible
                && _alertsList.SelectedItems.Count == 0)
            {
                inserted.Selected = true;
                inserted.Focused = true;
                inserted.EnsureVisible();
            }
        }

        // Mirror the most recent 10 into the Status page "Recent Alerts" list
        var recent = new ListViewItem(a.Timestamp.ToString("HH:mm:ss"));
        recent.SubItems.Add(a.Severity.ToString().ToUpperInvariant());
        recent.SubItems.Add(a.Category);
        recent.SubItems.Add(a.Title);
        recent.ForeColor = Theme.SeverityColor(a.Severity);
        _recentList.Items.Insert(0, recent);
        while (_recentList.Items.Count > 10)
            _recentList.Items.RemoveAt(_recentList.Items.Count - 1);
    }

    private void OnAlertSelected(object? sender, EventArgs e)
    {
        if (_alertsList.SelectedItems.Count == 0) { ClearAlertDetail(); return; }
        var item = _alertsList.SelectedItems[0];
        if (item.Tag is Alert a)
        {
            ShowAlertDetail(a);
            item.SubItems[3].Text =
                GetAlertActionState(a).Mitigated
                    ? $"[MITIGATED] {a.Title}"
                    : a.Title;
        }
    }

    private void ClearAlertDetail()
    {
        _selectedAlert = null;
        _alertDetailTitle.Text = "Select an alert to view details";
        _alertDetailTitle.ForeColor = Theme.TextDim;
        _alertDetailBody.Text = "";
        _alertDetailBody.Visible = false;
        _btnIpLookup.Visible    = false;
        _btnOpenLog.Visible     = false;
        _btnRegedit.Visible     = false;
        _btnInspectThreat.Visible = false;
        _btnRemediate.Visible = false;
        _btnUndoRemediation.Visible = false;
        _btnBlockIp.Visible     = false;
        _btnKillProcess.Visible = false;
        _btnCopyRow.Visible     = false;
        _btnCopyMessage.Visible = false;
    }

    private void ShowAlertDetail(Alert a)
    {
        _selectedAlert = a;
        _alertDetailTitle.Text = a.Title;
        _alertDetailTitle.ForeColor = a.Severity is AlertSeverity.Crit or AlertSeverity.High
            ? Theme.SevCrit
            : Theme.AccentBlue;

        // Full detail and the response actions are simply how an alert is
        // shown. They used to sit behind a "Detailed Threat Info" toggle
        // that defaulted to off, so a fresh install answered every alert
        // with no actions and no explanation.
        _alertDetailBody.Visible = true;
        _btnCopyRow.Visible     = true;
        _btnCopyMessage.Visible = true;

        var actionState = GetAlertActionState(a);
        var body = new System.Text.StringBuilder();
        body.AppendLine($"Time:     {a.Timestamp:yyyy-MM-dd HH:mm:ss}");
        body.AppendLine($"Severity: {a.Severity}");
        body.AppendLine($"Category: {a.Category}");
        body.AppendLine();
        body.AppendLine(a.Message);
        if (a.ProcessName is not null)
            body.AppendLine($"\nProcess:  {a.ProcessName} (PID {a.ProcessId})");
        if (a.RemoteIp is not null)
            body.AppendLine($"Remote:   {a.RemoteIp}:{a.RemotePort}");
        if (a.Path is not null)
            body.AppendLine($"Path:     {a.Path}");
        if (a.Extra is not null)
            foreach (var kv in a.Extra)
                if (!kv.Key.StartsWith("_", StringComparison.Ordinal))
                    body.AppendLine($"{kv.Key,-12}{kv.Value}");
        if (!string.IsNullOrWhiteSpace(actionState.Inspection))
        {
            body.AppendLine();
            body.AppendLine("--- Inspection ---");
            body.AppendLine(actionState.Inspection);
        }
        if (!string.IsNullOrWhiteSpace(actionState.Status))
        {
            body.AppendLine();
            body.AppendLine("--- Response status ---");
            body.AppendLine(actionState.Status);
        }
        _alertDetailBody.Text = body.ToString();

        // Action button visibility
        _btnIpLookup.Visible    = a.RemoteIp is not null;
        _btnBlockIp.Visible     = a.RemoteIp is not null
            && actionState.BlockedIp is null;
        var filePath = ThreatPath.Normalize(a.Path);
        _btnOpenLog.Visible     =
            filePath is not null && File.Exists(filePath);
        _btnRegedit.Visible     = HasRegistryLocation(a);
        _btnInspectThreat.Visible = CanInspect(a);
        _btnRemediate.Visible = CanRemediate(a);
        _btnRemediate.Text = RemediationButtonText(a);
        _btnUndoRemediation.Visible =
            actionState.Quarantine is not null
            || actionState.ServiceRestorePayload is not null
            || actionState.BlockedIp is not null;
        _btnUndoRemediation.Text = actionState.Quarantine is not null
            ? "Restore File"
            : actionState.ServiceRestorePayload is not null
                ? "Restore Service"
                : actionState.BlockedIp is not null
                    ? "Unblock IP"
                    : "Undo";
        if (a.ProcessId is int pid && pid > 0)
        {
            _btnKillProcess.Visible = true;
            _btnKillProcess.Text = $"Kill PID {pid}";
        }
        else
        {
            _btnKillProcess.Visible = false;
        }
    }

    // -----------------------------------------------------------------------
    //  Alert detail action handlers
    // -----------------------------------------------------------------------

    private void OnIpLookupClick(object? sender, EventArgs e)
    {
        if (_selectedAlert?.RemoteIp is not string ip) return;
        if (!IPAddress.TryParse(ip, out var address))
        {
            MessageBox.Show(this, "This alert does not contain a valid IP address.",
                "IP Lookup", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        var canonicalIp = address.ToString();
        if (MessageBox.Show(this,
            $"Open IPinfo in your browser to look up {canonicalIp}?\n\n" +
            "IPinfo will receive this IP address, your browser connection's " +
            "public IP address, and normal browser request information. " +
            "Its privacy policy is at https://ipinfo.io/privacy-policy.\n\n" +
            "No other alert details are sent. Choose No to cancel without contacting IPinfo.",
            "Share IP address with IPinfo?", MessageBoxButtons.YesNo,
            MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
            return;
        try
        {
            Process.Start(new ProcessStartInfo("https://ipinfo.io/" + Uri.EscapeDataString(canonicalIp))
            {
                UseShellExecute = true,
            });
        }
        catch (Exception ex) { _logger.Error($"IP lookup: {ex.Message}"); }
    }

    private void OnOpenLogClick(object? sender, EventArgs e)
    {
        var p = ThreatPath.Normalize(_selectedAlert?.Path);
        if (p is null || !File.Exists(p)) return;
        try
        {
            Process.Start(new ProcessStartInfo(
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"), $"/select,\"{p}\"")
            {
                UseShellExecute = true,
            });
        }
        catch (Exception ex) { _logger.Error($"Open log: {ex.Message}"); }
    }

    private void OnRegeditClick(object? sender, EventArgs e)
    {
        try
        {
            var use32BitView = false;
            if (_selectedAlert?.Extra is not null
                && _selectedAlert.Extra.TryGetValue(
                    "RegistryPath", out var registryPath))
            {
                using var key = Registry.CurrentUser.CreateSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Applets\Regedit");
                key?.SetValue("LastKey", registryPath);
                use32BitView =
                    Environment.Is64BitOperatingSystem
                    && _selectedAlert.Extra.TryGetValue(
                        "RegistryView", out var view)
                    && view == "32";
            }
            var executable = use32BitView
                ? Path.Combine(
                    Environment.GetFolderPath(
                        Environment.SpecialFolder.Windows),
                    "SysWOW64", "regedit.exe")
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "regedit.exe");
            Process.Start(new ProcessStartInfo(executable)
            {
                Arguments = "-m",
                UseShellExecute = true,
            });
        }
        catch (Exception ex) { _logger.Error($"Regedit: {ex.Message}"); }
    }

    private async void OnInspectThreatClick(object? sender, EventArgs e)
    {
        var alert = _selectedAlert;
        if (alert is null || !CanInspect(alert)) return;

        SetAlertActionsEnabled(false);
        try
        {
            var inspection = await Task.Run(
                () => BuildInspectionText(alert));
            var state = GetAlertActionState(alert);
            state.Inspection = inspection;
            state.Status = "Inspection completed. No system state was changed.";
            RefreshAlertPresentation(alert);
        }
        catch (Exception ex)
        {
            GetAlertActionState(alert).Status =
                $"Inspection failed: {ex.Message}";
            RefreshAlertPresentation(alert);
        }
        finally
        {
            SetAlertActionsEnabled(true);
        }
    }

    private async void OnRemediateClick(object? sender, EventArgs e)
    {
        var alert = _selectedAlert;
        if (alert is null || !CanRemediate(alert)) return;
        var state = GetAlertActionState(alert);

        if (state.Quarantine is not null)
        {
            var answer = MessageBox.Show(
                "Permanently delete the quarantined copy?\n\n" +
                "This cannot be undone.",
                "Permanent Delete - Confirm",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning);
            if (answer != DialogResult.Yes) return;

            SetAlertActionsEnabled(false);
            var deletion = await Task.Run(
                () => QuarantineManager.DeletePermanently(
                    state.Quarantine));
            state.Status = deletion.Message;
            if (deletion.Success)
                state.Quarantine = null;
            SetAlertActionsEnabled(true);
            RefreshAlertPresentation(alert);
            return;
        }

        if (alert.Category == "Registry"
            && RegistryRollbackService.CanRollback(alert))
        {
            var answer = MessageBox.Show(
                "Roll back this registry change to the value captured " +
                "immediately before the alert?\n\n" +
                "The action will be cancelled if the value has changed " +
                "again. HKLM changes require administrator approval.",
                "Registry Rollback - Confirm",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning);
            if (answer != DialogResult.Yes) return;

            SetAlertActionsEnabled(false);
            var result = await Task.Run(
                () => RegistryRollbackService.Rollback(alert, _logger));
            state.Status = result.Message;
            state.Mitigated = result.Success;
            SetAlertActionsEnabled(true);
            RefreshAlertPresentation(alert);
            return;
        }

        if (TryGetServiceName(alert, out var serviceName))
        {
            var noun = alert.Category is "Driver" or "BYOVD"
                ? "driver service"
                : "service";
            var answer = MessageBox.Show(
                $"Stop and disable {noun} '{serviceName}'?\n\n" +
                "The original start mode will be retained for a Restore " +
                "action. A loaded driver may remain active until restart.\n\n" +
                "Administrator approval is required.",
                "Service Deactivation - Confirm",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning);
            if (answer != DialogResult.Yes) return;

            SetAlertActionsEnabled(false);
            var result = await Task.Run(
                () => ServiceRemediationService.Disable(
                    serviceName, _logger));
            state.Status = result.Message;
            if (result.Success)
            {
                state.Mitigated = true;
                state.ServiceRestorePayload = result.RestorePayload;
            }
            SetAlertActionsEnabled(true);
            RefreshAlertPresentation(alert);
            return;
        }

        var path = ThreatPath.Normalize(alert.Path);
        if (path is null || !File.Exists(path)) return;
        var quarantineAnswer = MessageBox.Show(
            $"Move this file to recoverable quarantine?\n\n{path}\n\n" +
            "It can be restored or permanently deleted afterward.",
            "Quarantine File - Confirm",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning);
        if (quarantineAnswer != DialogResult.Yes) return;

        SetAlertActionsEnabled(false);
        var quarantine = await Task.Run(
            () => QuarantineManager.Quarantine(path));
        state.Status = quarantine.Message;
        if (quarantine.Success)
        {
            state.Mitigated = true;
            state.Quarantine = quarantine.Record;
        }
        SetAlertActionsEnabled(true);
        RefreshAlertPresentation(alert);
    }

    private async void OnUndoRemediationClick(object? sender, EventArgs e)
    {
        var alert = _selectedAlert;
        if (alert is null) return;
        var state = GetAlertActionState(alert);

        if (state.Quarantine is not null)
        {
            var answer = MessageBox.Show(
                $"Restore the quarantined file?\n\n" +
                $"{state.Quarantine.OriginalPath}",
                "Restore File - Confirm",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning);
            if (answer != DialogResult.Yes) return;
            SetAlertActionsEnabled(false);
            var result = await Task.Run(
                () => QuarantineManager.Restore(state.Quarantine));
            state.Status = result.Message;
            if (result.Success)
            {
                state.Quarantine = null;
                state.Mitigated = false;
            }
        }
        else if (state.ServiceRestorePayload is not null)
        {
            var answer = MessageBox.Show(
                "Restore the service's original start mode and running state?",
                "Restore Service - Confirm",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning);
            if (answer != DialogResult.Yes) return;
            SetAlertActionsEnabled(false);
            var result = await Task.Run(
                () => ServiceRemediationService.Restore(
                    state.ServiceRestorePayload, _logger));
            state.Status = result.Message;
            if (result.Success)
            {
                state.ServiceRestorePayload = null;
                state.Mitigated = false;
            }
        }
        else if (state.BlockedIp is not null)
        {
            var blockedIp = state.BlockedIp;
            var answer = MessageBox.Show(
                $"Remove Whitehat Security firewall rules for {blockedIp}?",
                "Unblock IP - Confirm",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question);
            if (answer != DialogResult.Yes) return;
            SetAlertActionsEnabled(false);
            var rc = await Task.Run(
                () => ElevationHelper.UnblockIpAddress(
                    blockedIp, _logger));
            state.Status = rc == 0
                ? $"IP {blockedIp} was unblocked."
                : $"IP unblock failed (exit {rc}).";
            if (rc == 0)
            {
                state.BlockedIp = null;
                state.Mitigated = false;
            }
        }

        SetAlertActionsEnabled(true);
        RefreshAlertPresentation(alert);
    }

    private async void OnBlockIpClick(object? sender, EventArgs e)
    {
        var alert = _selectedAlert;
        if (alert?.RemoteIp is not string ip) return;
        var result = MessageBox.Show(
            $"Block IP address {ip}?\n\nThis creates two Windows Firewall rules\n(WHS_Block_{ip}_In and _Out).\n\nA UAC prompt will appear.",
            "Block IP - Confirm",
            MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
        if (result != DialogResult.Yes) return;

        SetAlertActionsEnabled(false);
        int rc = await Task.Run(
            () => ElevationHelper.BlockIpAddress(ip, _logger));
        SetAlertActionsEnabled(true);
        var state = GetAlertActionState(alert);
        state.Status = rc == 0
            ? $"IP {ip} was blocked by inbound and outbound firewall rules."
            : $"IP block failed (exit {rc}).";
        if (rc == 0)
        {
            state.Mitigated = true;
            state.BlockedIp = ip;
        }
        RefreshAlertPresentation(alert);
        MessageBox.Show(
            rc == 0 ? $"IP {ip} blocked." : $"Failed (exit {rc}).",
            "Block IP",
            MessageBoxButtons.OK,
            rc == 0 ? MessageBoxIcon.Information : MessageBoxIcon.Error);
    }

    private void OnKillProcessClick(object? sender, EventArgs e)
    {
        if (_selectedAlert?.ProcessId is not int pid || pid <= 0) return;
        var result = MessageBox.Show(
            $"Terminate {_selectedAlert.ProcessName ?? "?"} (PID {pid})?\n\nA UAC prompt will appear if needed.",
            "Kill Process - Confirm",
            MessageBoxButtons.YesNo, MessageBoxIcon.Question);
        if (result != DialogResult.Yes) return;

        try
        {
            using var process = Process.GetProcessById(pid);
            if (!string.IsNullOrWhiteSpace(_selectedAlert.ProcessName)
                && !string.Equals(
                    process.ProcessName,
                    _selectedAlert.ProcessName,
                    StringComparison.OrdinalIgnoreCase))
            {
                MessageBox.Show(
                    "The process ID now belongs to a different process. The action was cancelled.",
                    "Kill Process",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
                return;
            }
            process.Kill();
            MarkAlertMitigated(
                _selectedAlert, "The detected process was terminated.");
            MessageBox.Show("Process killed.", "Kill Process", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch
        {
            int rc = ElevationHelper.KillProcessElevated(pid, _logger);
            if (rc == 0)
                MarkAlertMitigated(
                    _selectedAlert, "The detected process was terminated.");
            MessageBox.Show(
                rc == 0 ? "Process killed." : $"Failed (exit {rc}).",
                "Kill Process", MessageBoxButtons.OK,
                rc == 0 ? MessageBoxIcon.Information : MessageBoxIcon.Error);
        }
    }

    private AlertActionState GetAlertActionState(Alert alert)
    {
        if (_alertActionStates.TryGetValue(alert, out var state))
            return state;
        state = new AlertActionState();
        if (alert.Path is not null)
            state.Quarantine = QuarantineManager.FindByOriginalPath(
                alert.Path);
        if (state.Quarantine is not null)
        {
            state.Mitigated = true;
            state.Status =
                $"File is in recoverable quarantine ({state.Quarantine.Id}).";
        }
        if (TryGetServiceName(alert, out var serviceName))
        {
            state.ServiceRestorePayload =
                ServiceRemediationService.FindRestorePayload(
                    serviceName);
            if (state.ServiceRestorePayload is not null)
            {
                state.Mitigated = true;
                state.Status =
                    "The service is disabled and has a saved restore state.";
            }
        }
        _alertActionStates[alert] = state;
        return state;
    }

    private bool CanInspect(Alert alert)
        => alert.Path is not null
            || HasRegistryLocation(alert)
            || TryGetServiceName(alert, out _)
            || alert.ProcessId is > 0
            || alert.RemoteIp is not null;

    private bool CanRemediate(Alert alert)
    {
        var state = GetAlertActionState(alert);
        if (state.Quarantine is not null) return true;
        if (state.Mitigated) return false;
        if (alert.Category == "Registry")
            return RegistryRollbackService.CanRollback(alert);
        if (TryGetServiceName(alert, out _)
            && !alert.Title.Contains(
                "REMOVED", StringComparison.OrdinalIgnoreCase))
            return true;
        var path = ThreatPath.Normalize(alert.Path);
        return path is not null
            && File.Exists(path)
            && !ThreatPath.IsProtectedSystemPath(path);
    }

    private string RemediationButtonText(Alert alert)
    {
        var state = GetAlertActionState(alert);
        if (state.Quarantine is not null)
            return "Delete Permanently";
        if (alert.Category == "Registry")
            return "Undo Registry Change";
        if (TryGetServiceName(alert, out _))
            return alert.Category is "Driver" or "BYOVD"
                ? "Disable Driver"
                : "Disable Service";
        return "Quarantine File";
    }

    private static bool TryGetServiceName(
        Alert alert, out string serviceName)
    {
        serviceName = "";
        if (alert.Extra is null
            || !alert.Extra.TryGetValue(
                "ServiceName", out var found)
            || !ServiceStatePayload.IsValidServiceName(found))
            return false;
        serviceName = found;
        return true;
    }

    private static bool HasRegistryLocation(Alert alert)
        => alert.Extra is not null
            && alert.Extra.TryGetValue(
                "RegistryPath", out var registryPath)
            && !string.IsNullOrWhiteSpace(registryPath);

    private static string BuildInspectionText(Alert alert)
    {
        var sections = new List<string>();
        var path = ThreatPath.Normalize(alert.Path);
        if (path is not null)
            sections.Add(FileInvestigator.Inspect(path).ToDisplayText());

        if (HasRegistryLocation(alert))
        {
            if (RegistryRollbackService.CanRollback(alert))
            {
                sections.Add(
                    RegistryRollbackService.Inspect(alert));
            }
            else
            {
                var registryPath =
                    alert.Extra!["RegistryPath"];
                alert.Extra.TryGetValue(
                    "ValueName", out var valueName);
                sections.Add(
                    $"Registry key: {registryPath}{Environment.NewLine}" +
                    $"Value:        {valueName ?? "(not specified)"}");
            }
        }

        if (TryGetServiceName(alert, out var serviceName))
            sections.Add(ServiceRemediationService.Inspect(serviceName));

        if (alert.ProcessId is int pid && pid > 0)
        {
            try
            {
                using var process = Process.GetProcessById(pid);
                var sameProcess = string.IsNullOrWhiteSpace(alert.ProcessName)
                    || string.Equals(
                        process.ProcessName,
                        alert.ProcessName,
                        StringComparison.OrdinalIgnoreCase);
                sections.Add(
                    $"Process: {process.ProcessName} (PID {pid}){Environment.NewLine}" +
                    $"State:   {(sameProcess ? "Running" : "PID reused by a different process")}");
            }
            catch
            {
                sections.Add(
                    $"Process: PID {pid}{Environment.NewLine}State:   Not running");
            }
        }

        if (alert.RemoteIp is not null)
            sections.Add(
                $"Remote IP: {alert.RemoteIp}{Environment.NewLine}" +
                $"Port:      {alert.RemotePort?.ToString() ?? "(unknown)"}");

        return sections.Count == 0
            ? "No category-specific inspection data is available."
            : string.Join(
                Environment.NewLine + Environment.NewLine,
                sections);
    }

    private void SetAlertActionsEnabled(bool enabled)
    {
        _btnInspectThreat.Enabled = enabled;
        _btnRemediate.Enabled = enabled;
        _btnUndoRemediation.Enabled = enabled;
        _btnIpLookup.Enabled = enabled;
        _btnOpenLog.Enabled = enabled;
        _btnRegedit.Enabled = enabled;
        _btnBlockIp.Enabled = enabled;
        _btnKillProcess.Enabled = enabled;
        if (!enabled)
            _btnRemediate.Text = "Working...";
    }

    private void MarkAlertMitigated(Alert? alert, string status)
    {
        if (alert is null) return;
        var state = GetAlertActionState(alert);
        state.Mitigated = true;
        state.Status = status;
        RefreshAlertPresentation(alert);
    }

    private void RefreshAlertPresentation(Alert alert)
    {
        foreach (ListViewItem item in _alertsList.Items)
        {
            if (ReferenceEquals(item.Tag, alert))
            {
                item.SubItems[3].Text =
                    GetAlertActionState(alert).Mitigated
                        ? $"[MITIGATED] {alert.Title}"
                        : alert.Title;
                break;
            }
        }
        if (ReferenceEquals(_selectedAlert, alert))
            ShowAlertDetail(alert);
    }

    // -----------------------------------------------------------------------
    //  Settings page wiring
    // -----------------------------------------------------------------------

    /// <summary>
    /// Single CheckedChanged handler for every checkbox on the Settings page.
    /// The Tag of each checkbox holds the JSON key name; we route on that.
    /// </summary>
    private async void OnSettingsCheckChanged(object? sender, EventArgs e)
    {
        if (sender is not CheckBox cb || cb.Tag is not string key) return;

#if STORE_BUILD
        if (!cb.Checked && (key is "FW_DomainProfile" or "FW_PrivateProfile" or "FW_PublicProfile"))
        {
            SetCheckedWithoutHandler(cb, true);
            MessageBox.Show(this,
                "This edition can enable Windows Firewall profiles but cannot disable " +
                "Windows security protections. Your firewall was not changed.",
                "Windows Firewall", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        if (key == "DNS_DoH")
        {
            SetCheckedWithoutHandler(cb, false);
            return;
        }
#endif

        switch (key)
        {
            case "Firmware":   _config.Firmware   = cb.Checked; break;
            case "Driver":     _config.Driver     = cb.Checked; break;
            case "Service":    _config.Service    = cb.Checked; break;
            case "Connection": _config.Connection = cb.Checked; break;
            case "Process":    _config.Process    = cb.Checked; break;
            case "Listener":   _config.Listener   = cb.Checked; break;
            case "Registry":   _config.Registry   = cb.Checked; break;
            case "Security":   _config.Security   = cb.Checked; break;
            case "RDP":        _config.RDP        = cb.Checked; break;
            case "Hosts":      _config.Hosts      = cb.Checked; break;
            case "HiddenProcess": _config.HiddenProcess = cb.Checked; break;
            case "Memory":     _config.Memory     = cb.Checked; break;
            case "BYOVD":      _config.BYOVD      = cb.Checked; break;

            case "EnableToastNotifications": _config.EnableToastNotifications = cb.Checked; break;
            case "BeepOnAlert":              _config.BeepOnAlert              = cb.Checked; break;

            case "FW_DomainProfile":  await TogglePrivilegedAsync(cb, () => _config.FW_DomainProfile  = cb.Checked,
                () => ElevationHelper.SetFirewallProfile("Domain",  cb.Checked, _logger)); break;
            case "FW_PrivateProfile": await TogglePrivilegedAsync(cb, () => _config.FW_PrivateProfile = cb.Checked,
                () => ElevationHelper.SetFirewallProfile("Private", cb.Checked, _logger)); break;
            case "FW_PublicProfile":  await TogglePrivilegedAsync(cb, () => _config.FW_PublicProfile  = cb.Checked,
                () => ElevationHelper.SetFirewallProfile("Public",  cb.Checked, _logger)); break;

            case "FW_BlockInbound":   await TogglePrivilegedAsync(cb, () => _config.FW_BlockInbound   = cb.Checked,
                () => ElevationHelper.SetBlockInboundRule(cb.Checked, _logger)); break;
            case "FW_BlockPing":      await TogglePrivilegedAsync(cb, () => _config.FW_BlockPing      = cb.Checked,
                () => ElevationHelper.SetBlockPingRule(cb.Checked, _logger)); break;
            case "FW_BlockLAN":
                if (cb.Checked && MessageBox.Show(
                    "WARNING: This isolates this PC from your local network. Continue?",
                    "Block LAN", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                {
                    SetCheckedWithoutHandler(cb, false); return;
                }
                await TogglePrivilegedAsync(cb, () => _config.FW_BlockLAN = cb.Checked,
                    () => ElevationHelper.SetBlockLanRule(cb.Checked, _logger));
                break;
            case "FW_BlockDevices":   await TogglePrivilegedAsync(cb, () => _config.FW_BlockDevices = cb.Checked,
                () => ElevationHelper.SetBlockDevicesRule(cb.Checked, _logger)); break;

            case "PF_BlockTrackers":  await TogglePrivilegedAsync(cb, () => _config.PF_BlockTrackers  = cb.Checked,
                () => ElevationHelper.SetHostsBlocklist("Trackers", cb.Checked, _logger)); break;
            case "PF_BlockMalware":   await TogglePrivilegedAsync(cb, () => _config.PF_BlockMalware   = cb.Checked,
                () => ElevationHelper.SetHostsBlocklist("Malware", cb.Checked, _logger)); break;
            case "PF_BlockTelemetry": await TogglePrivilegedAsync(cb, () => _config.PF_BlockTelemetry = cb.Checked,
                () => ElevationHelper.SetHostsBlocklist("Telemetry", cb.Checked, _logger)); break;

            case "DNS_DoH":
                var dnsApplied = await TogglePrivilegedAsync(
                    cb,
                    () => _config.DNS_DoH = cb.Checked,
                    () => ElevationHelper.SetDnsOverHttps(
                        cb.Checked, _config.DNS_Provider, _logger));
                SetDnsStatus(
                    dnsApplied
                        ? cb.Checked
                            ? "Secure DNS applied and verified"
                            : "Secure DNS disabled and verified"
                        : "Secure DNS change failed",
                    dnsApplied ? Theme.Green : Theme.Red);
                break;
        }

        SaveConfigSafe();
    }

    private async void OnDnsProviderChanged(object? sender, EventArgs e)
    {
        if (sender is not ComboBox cmb) return;
        var picked = cmb.SelectedItem?.ToString() ?? "None";
        await ApplyDnsProviderAsync(cmb, picked, force: false);
    }

    private async void OnApplyDnsClick(object? sender, EventArgs e)
    {
        if (_dnsProviderCombo is not ComboBox cmb) return;
        var picked = cmb.SelectedItem?.ToString() ?? "None";
        await ApplyDnsProviderAsync(cmb, picked, force: true);
    }

    private async Task ApplyDnsProviderAsync(
        ComboBox cmb,
        string picked,
        bool force)
    {
        var previousProvider = _config.DNS_Provider;
        if (!force && picked == previousProvider) return;

        if (picked != "None" && MessageBox.Show(this,
            $"Apply {picked} as the DNS provider for active network adapters?\n\n" +
            "This provider will receive subsequent DNS queries and the connection's " +
            "public IP address. Review the provider's privacy policy before continuing. " +
            "You can change the provider later in this app or Windows network settings.",
            "Change DNS provider?", MessageBoxButtons.YesNo, MessageBoxIcon.Question,
            MessageBoxDefaultButton.Button2) != DialogResult.Yes)
        {
            RevertDnsCombo(cmb, previousProvider);
            return;
        }

#if STORE_BUILD
        // The Store edition leaves encryption controls to Windows Settings.
        // An imported preference must not trigger the direct-registry DoH path.
        var hadDoh = false;
#else
        var hadDoh = _config.DNS_DoH;
#endif
        var disabledPreviousDoh = false;
        cmb.Enabled = false;
        if (_dnsApplyButton is not null)
            _dnsApplyButton.Enabled = false;
        SetDnsStatus(
            picked == "None"
                ? "Restoring automatic DNS..."
                : $"Applying {picked}...",
            Theme.Orange);

        int rc = 0;
        try
        {
            if (hadDoh && picked != previousProvider)
            {
                rc = await Task.Run(() =>
                    ElevationHelper.SetDnsOverHttps(
                        false, previousProvider, _logger));
                if (rc != 0)
                {
                    RevertDnsCombo(cmb, previousProvider);
                    SetDnsStatus(
                        "Could not disable the previous Secure DNS setting",
                        Theme.Red);
                    ShowDnsFailure(
                        rc, "disable the previous Secure DNS setting");
                    return;
                }
                disabledPreviousDoh = true;
            }

            rc = await Task.Run(
                () => ElevationHelper.SetDnsProvider(picked, _logger));
            if (rc != 0)
            {
                if (disabledPreviousDoh)
                {
                    var restoreDohRc = await Task.Run(() =>
                        ElevationHelper.SetDnsOverHttps(
                            true, previousProvider, _logger));
                    if (restoreDohRc != 0)
                    {
                        _config.DNS_DoH = false;
                        SaveConfigSafe();
                    }
                }
                RevertDnsCombo(cmb, previousProvider);
                SetDnsStatus("DNS change failed; previous settings restored",
                    Theme.Red);
                ShowDnsFailure(rc, $"apply {picked}");
                return;
            }

            _config.DNS_Provider = picked;
            _config.DNS_DoH =
                hadDoh && DnsConfiguration.SupportsDoh(picked);

            if (_config.DNS_DoH)
            {
                var dohRc = await Task.Run(() =>
                    ElevationHelper.SetDnsOverHttps(
                        true, picked, _logger));
                if (dohRc != 0)
                {
                    _config.DNS_DoH = false;
                    SaveConfigSafe();
                    SetDnsStatus(
                        $"{picked} applied; Secure DNS failed",
                        Theme.Orange);
                    MessageBox.Show(
                        "The DNS provider was applied and verified, but " +
                        "DNS-over-HTTPS could not be enabled. Secure DNS " +
                        "was turned off so the dashboard matches Windows.",
                        "Whitehat Security",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning);
                    ApplyDnsControlState();
                    return;
                }
            }

            SaveConfigSafe();
            SetDnsStatus(
                picked == "None"
                    ? "Automatic DNS restored and verified"
                    : (_config.DNS_DoH
                        ? $"{picked} + Secure DNS applied and verified"
                        : $"{picked} applied and verified")
                      + DescribeIpv6Coverage(picked),
                Theme.Green);
            ApplyDnsControlState();
        }
        finally
        {
            if (!cmb.IsDisposed) cmb.Enabled = true;
            if (_dnsApplyButton is not null
                && !_dnsApplyButton.IsDisposed)
                _dnsApplyButton.Enabled = true;
        }
    }

    private void RevertDnsCombo(
        ComboBox combo,
        string provider)
    {
        combo.SelectedIndexChanged -= OnDnsProviderChanged;
        combo.SelectedItem = provider;
        combo.SelectedIndexChanged += OnDnsProviderChanged;
    }

    /// <summary>
    /// The apply script configures the provider's IPv6 resolvers only on
    /// interfaces that hold an IPv6 default route. Without this note a user
    /// on an IPv4-only network sees "applied and verified" and then finds
    /// IPv6 DNS unchanged, with nothing explaining why.
    /// </summary>
    private static string DescribeIpv6Coverage(string providerName)
    {
        if (!DnsConfiguration.TryGetProvider(providerName, out var provider)
            || provider is null)
            return string.Empty;
        return DnsConfiguration.IsProviderIpv6Active(provider)
            ? " (IPv4 + IPv6)"
            : " (IPv4 only — this network has no IPv6 route)";
    }

    private void SetDnsStatus(string text, Color color)
    {
        if (_dnsStatusLabel is null || _dnsStatusLabel.IsDisposed)
            return;
        _dnsStatusLabel.Text = text;
        _dnsStatusLabel.ForeColor = color;
    }

    private void ShowDnsFailure(int result, string action)
    {
        MessageBox.Show(
            $"Could not {action}: {DescribeElevationFailure(result)}\n\n" +
            "The system was rolled back when possible. See the Console " +
            "or log for the exact Windows error.",
            "Whitehat Security",
            MessageBoxButtons.OK,
            MessageBoxIcon.Warning);
    }

    /// <summary>
    /// Helper that runs a privileged action via UAC, then either persists the
    /// new value or reverts the checkbox state if elevation failed.
    /// </summary>
    private async Task<bool> TogglePrivilegedAsync(
        CheckBox cb, Action persist, Func<int> action)
    {
        cb.Enabled = false;
        int rc;
        try { rc = await Task.Run(action); }
        finally
        {
            if (!cb.IsDisposed) cb.Enabled = true;
        }
        if (rc == 0)
        {
            persist();
            SaveConfigSafe();
            return true;
        }
        else
        {
            // Revert visual state — user denied UAC, the helper failed,
            // or the elevated script returned non-zero.
            SetCheckedWithoutHandler(cb, !cb.Checked);

            // Surface the failure so the user understands why the toggle
            // bounced back. Previous versions reverted silently, which made
            // it look like the checkbox was simply broken.
            MessageBox.Show(
                $"Could not apply '{cb.Tag}': " +
                $"{DescribeElevationFailure(rc)}\n\n" +
                "The checkbox has been reverted.",
                "Whitehat Security",
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return false;
        }
    }

    private static string DescribeElevationFailure(int result) =>
        result switch
        {
            -2 => "the elevated PowerShell timed out (30 s limit).",
            -3 => "the elevation request failed (UAC declined or system error).",
            -4 => "the input value was empty or invalid.",
            -5 => "the input value was rejected as unsafe.",
            -6 => "this operation is disabled because it could also block the Windows DNS client.",
            6  => "DNS-over-HTTPS is not supported by this Windows installation.",
            _  => $"the elevated script exited with code {result}.",
        };

    private void SetCheckedWithoutHandler(CheckBox cb, bool value)
    {
        cb.CheckedChanged -= OnSettingsCheckChanged;
        cb.Checked = value;
        cb.CheckedChanged += OnSettingsCheckChanged;
    }

    // -----------------------------------------------------------------------
    //  Settings page action buttons (Reset / Export / Import)
    // -----------------------------------------------------------------------

    private void OnResetSettingsClick(object? sender, EventArgs e)
    {
        var ans = MessageBox.Show(
            "Reset notification and display preferences to defaults?\n\n" +
            "Firewall, hosts-file, and DNS settings will not be changed.",
            "Reset App Preferences",
            MessageBoxButtons.YesNo, MessageBoxIcon.Question);
        if (ans != DialogResult.Yes) return;

        var fresh = NotifyConfig.Defaults();
        // Mutate _config in place so every other UI element that holds a
        // reference (the toast notifier, the alert gate via MonitorHost)
        // observes the new values immediately.
        CopyAppPreferences(fresh, _config);
        SaveConfigSafe();
        ApplyConfigToSettingsCheckboxes();
    }

    private void OnExportSettingsClick(object? sender, EventArgs e)
    {
        try
        {
            using var dlg = new SaveFileDialog
            {
                Filter   = "JSON (*.json)|*.json|All files (*.*)|*.*",
                FileName = $"WhitehatSecurity_Config_{DateTime.Now:yyyyMMdd_HHmmss}.json",
            };
            if (dlg.ShowDialog() != DialogResult.OK) return;
            _config.Save(dlg.FileName);
            MessageBox.Show("Settings exported.", "Export",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex) { _logger.Error($"Export settings: {ex.Message}"); }
    }

    private void OnImportSettingsClick(object? sender, EventArgs e)
    {
        try
        {
            using var dlg = new OpenFileDialog
            {
                Filter = "JSON (*.json)|*.json|All files (*.*)|*.*",
            };
            if (dlg.ShowDialog() != DialogResult.OK) return;
            var loaded = NotifyConfig.LoadStrict(dlg.FileName);
            CopyAppPreferences(loaded, _config);
            SaveConfigSafe();
            ApplyConfigToSettingsCheckboxes();
            MessageBox.Show(
                "Notification and display preferences imported. System-level firewall, hosts-file, and DNS settings were left unchanged.",
                "Import",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            _logger.Error($"Import settings: {ex.Message}");
            MessageBox.Show($"Import failed: {ex.Message}", "Import",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    /// <summary>
    /// Copy every settable property from <paramref name="src"/> into
    /// <paramref name="dst"/>. Used by the Reset / Import paths so the
    /// existing _config reference (held by sinks, gates, etc.) is updated
    /// in place rather than replaced.
    /// </summary>
    private static void CopyAppPreferences(
        NotifyConfig src, NotifyConfig dst)
    {
        dst.SchemaVersion            = src.SchemaVersion;
        dst.Firmware                 = src.Firmware;
        dst.Driver                   = src.Driver;
        dst.Service                  = src.Service;
        dst.Connection               = src.Connection;
        dst.Process                  = src.Process;
        dst.Listener                 = src.Listener;
        dst.Registry                 = src.Registry;
        dst.Security                 = src.Security;
        dst.RDP                      = src.RDP;
        dst.Hosts                    = src.Hosts;
        dst.HiddenProcess            = src.HiddenProcess;
        dst.Memory                   = src.Memory;
        dst.BYOVD                    = src.BYOVD;
        dst.EnableToastNotifications = src.EnableToastNotifications;
        dst.BeepOnAlert              = src.BeepOnAlert;
    }

    /// <summary>
    /// Re-sync every Settings checkbox from the live _config object.
    /// Used after Reset / Import so the visible state reflects the new
    /// values without needing to rebuild the page.
    /// </summary>
    private void ApplyConfigToSettingsCheckboxes()
    {
        foreach (var (key, cb) in _settingsCheckboxes)
        {
            // Detach + reattach so the assignment doesn't fire the change
            // handler (which would try to re-run any privileged side effect).
            cb.CheckedChanged -= OnSettingsCheckChanged;
            cb.Checked = key switch
            {
                "Firmware"                 => _config.Firmware,
                "Driver"                   => _config.Driver,
                "Service"                  => _config.Service,
                "Connection"               => _config.Connection,
                "Process"                  => _config.Process,
                "Listener"                 => _config.Listener,
                "Registry"                 => _config.Registry,
                "Security"                 => _config.Security,
                "RDP"                      => _config.RDP,
                "Hosts"                    => _config.Hosts,
                "HiddenProcess"            => _config.HiddenProcess,
                "Memory"                   => _config.Memory,
                "BYOVD"                    => _config.BYOVD,
                "EnableToastNotifications" => _config.EnableToastNotifications,
                "BeepOnAlert"              => _config.BeepOnAlert,
                "FW_DomainProfile"         => _config.FW_DomainProfile,
                "FW_PrivateProfile"        => _config.FW_PrivateProfile,
                "FW_PublicProfile"         => _config.FW_PublicProfile,
                "FW_BlockInbound"          => _config.FW_BlockInbound,
                "FW_BlockPing"             => _config.FW_BlockPing,
                "FW_BlockLAN"              => _config.FW_BlockLAN,
                "FW_BlockDevices"          => _config.FW_BlockDevices,
                "PF_BlockTrackers"         => _config.PF_BlockTrackers,
                "PF_BlockMalware"          => _config.PF_BlockMalware,
                "PF_BlockTelemetry"        => _config.PF_BlockTelemetry,
                "DNS_DoH"                  => _config.DNS_DoH,
                _                          => cb.Checked,
            };
            cb.CheckedChanged += OnSettingsCheckChanged;
        }
        if (_dnsProviderCombo is not null)
        {
            _dnsProviderCombo.SelectedIndexChanged -= OnDnsProviderChanged;
            _dnsProviderCombo.SelectedItem = _config.DNS_Provider;
            _dnsProviderCombo.SelectedIndexChanged += OnDnsProviderChanged;
        }
        ApplyDnsControlState();
    }

    private void ApplyDnsControlState()
    {
        if (!_settingsCheckboxes.TryGetValue("DNS_DoH", out var doh))
            return;
        var supported =
            DnsConfiguration.SupportsDoh(_config.DNS_Provider);
        doh.Enabled = supported;
        if (!supported && doh.Checked)
        {
            SetCheckedWithoutHandler(doh, false);
            _config.DNS_DoH = false;
            SaveConfigSafe();
        }
    }

    private void SaveConfigSafe()
    {
        try { _config.Save(_configPath); }
        catch (Exception ex) { _logger.Error($"Save config: {ex.Message}"); }
    }

    // -----------------------------------------------------------------------
    //  Status page refresh
    // -----------------------------------------------------------------------

    /// <summary>
    /// Cached process count, refreshed every ~6 s by RefreshStatusPage.
    /// Process.GetProcesses() allocates a Process object per kernel handle
    /// (~500 objects on a typical desktop) and cannot be made cheap, so we
    /// throttle it independently from the rest of the cards.
    /// </summary>
    private int _cachedProcessCount = 0;
    private long _lastProcessCountTick = 0;

    /// <summary>
    /// Same throttle for the active TCP connection count — IPGlobalProperties
    /// pivots through GetTcpTable which can be slow when the system has
    /// thousands of half-closed sockets.
    /// </summary>
    private int _cachedConnCount = 0;
    private long _lastConnCountTick = 0;

    private void RefreshStatusPage()
    {
        try
        {
            // _sink.Count is O(1) and lock-cheap; _sink.All would allocate
            // a snapshot array on every status refresh.
            _alertCountValue.Text = _sink.Count.ToString();

            // Only re-query the heavy counters every ~6 s. The 2 s timer
            // tick still updates uptime + alert count cheaply.
            long now = Environment.TickCount64;
            if (now - _lastConnCountTick > 6000)
            {
                try
                {
                    _cachedConnCount = System.Net.NetworkInformation.IPGlobalProperties
                        .GetIPGlobalProperties()
                        .GetActiveTcpConnections().Length;
                }
                catch { /* leave previous value */ }
                _lastConnCountTick = now;
            }
            _connCountValue.Text = _cachedConnCount.ToString();

            if (now - _lastProcessCountTick > 6000)
            {
                try
                {
                    var ps = Process.GetProcesses();
                    _cachedProcessCount = ps.Length;
                    foreach (var p in ps) p.Dispose();   // release the handles
                }
                catch { /* leave previous value */ }
                _lastProcessCountTick = now;
            }
            _procCountValue.Text = _cachedProcessCount.ToString();

            // Uptime is "time since this WhitehatSecurity process started",
            // not "time since boot". Environment.TickCount64 was wrong; use
            // the captured start time so the value matches the Started:
            // line in the info row.
            var up = DateTime.Now - Program.StartedAt;
            _uptimeValue.Text = $"{(int)up.TotalHours:D2}:{up.Minutes:D2}";
        }
        catch
        {
            // Status panel failures are cosmetic — never let them throw
        }
    }

    // -----------------------------------------------------------------------
    //  Console page refresh
    // -----------------------------------------------------------------------

    private void OnConsoleLineAppended(string line)
    {
        if (IsDisposed) return;
        if (InvokeRequired)
        {
            try { BeginInvoke(new Action<string>(OnConsoleLineAppended), line); }
            catch { }
            return;
        }
        AppendConsoleLine(line);
    }

    private void AppendConsoleLine(string line)
    {
        // Pick a colour based on the level marker so the user can scan
        // for warnings / errors / alerts visually instead of reading
        // every line.
        var colour = _consoleBox.ForeColor;
        if      (line.Contains("[ERROR]")) colour = Theme.Red;
        else if (line.Contains("[WARN]"))  colour = Theme.Orange;
        else if (line.Contains("[ALERT]")) colour = Theme.SevCrit;
        else if (line.Contains("[INFO]"))  colour = Theme.Green;

        int selStartBefore = _consoleBox.SelectionStart;
        int selLenBefore   = _consoleBox.SelectionLength;

        _consoleBox.SelectionStart  = _consoleBox.TextLength;
        _consoleBox.SelectionLength = 0;
        _consoleBox.SelectionColor  = colour;
        _consoleBox.AppendText(line + Environment.NewLine);
        _consoleBox.SelectionColor  = _consoleBox.ForeColor;
        if (_consoleBox.Lines.Length > 2050)
        {
            var cutoff = _consoleBox.GetFirstCharIndexFromLine(
                _consoleBox.Lines.Length - 2000);
            if (cutoff > 0)
            {
                _consoleBox.Select(0, cutoff);
                _consoleBox.SelectedText = string.Empty;
            }
        }

        if (_consoleAutoScroll.Checked)
        {
            _consoleBox.SelectionStart = _consoleBox.TextLength;
            _consoleBox.ScrollToCaret();
        }
        else
        {
            // Restore the user's caret position so the view doesn't yank.
            _consoleBox.SelectionStart  = selStartBefore;
            _consoleBox.SelectionLength = selLenBefore;
        }

        // Update the dropped-line counter so the user can see when the
        // ring buffer started evicting older lines.
        try
        {
            int dropped = _consoleSink.LinesDropped;
            _consoleDroppedLabel.Text = dropped > 0
                ? $"({dropped} line{(dropped == 1 ? "" : "s")} dropped — buffer full)"
                : "";
        }
        catch { }
    }

    private void OnClearConsoleClick(object? sender, EventArgs e)
    {
        _consoleSink.Clear();
        _consoleBox.Clear();
        _consoleDroppedLabel.Text = "";
    }

    private void OnSaveConsoleClick(object? sender, EventArgs e)
    {
        try
        {
            using var dlg = new SaveFileDialog
            {
                Filter   = "Text (*.txt)|*.txt|All files (*.*)|*.*",
                FileName = $"WhitehatSecurity_Console_{DateTime.Now:yyyyMMdd_HHmmss}.txt",
            };
            if (dlg.ShowDialog() != DialogResult.OK) return;
            File.WriteAllText(dlg.FileName, _consoleBox.Text);
        }
        catch (Exception ex) { _logger.Error($"Save console: {ex.Message}"); }
    }

    // -----------------------------------------------------------------------
    //  Logs page file-card click handlers
    // -----------------------------------------------------------------------

    private void OnOpenFileClick(object? sender, EventArgs e)
    {
        if (sender is not Control ctl || ctl.Tag is not string path) return;
        try
        {
            if (File.Exists(path))
                Process.Start(new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe"), '"' + path + '"') { UseShellExecute = true });
            else
                MessageBox.Show($"Not yet created:\n{path}", "Logs", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex) { _logger.Error($"Open log: {ex.Message}"); }
    }
}
