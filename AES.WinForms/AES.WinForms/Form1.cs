using System.Globalization;
using AES.WinForms.Controls;
using AES.WinForms.Models;
using AES.WinForms.Native;
using AES.WinForms.Services;

namespace AES.WinForms;

public sealed class Form1 : Form
{
    private readonly PasswordDerivationService _passwordDerivationService = new();
    private readonly ManagedCryptoService _managedCryptoService = new();
    private readonly NativeCryptoFacade _nativeCryptoFacade = new();
    private readonly BenchmarkCsvService _benchmarkCsvService = new();
    private readonly SingleFileCryptoService _singleFileCryptoService;
    private readonly BenchmarkService _benchmarkService;
    private readonly EnvironmentInspectionService _environmentInspectionService;

    private BenchmarkSession? _currentBenchmarkSession;
    private SingleFilePackageInfo? _currentSingleFilePackageInfo;
    private CancellationTokenSource? _benchmarkCancellationTokenSource;

    private readonly TabControl _tabControl = new() { Dock = DockStyle.Fill };
    private readonly ComboBox _benchmarkAlgorithmComboBox = CreateDropDown();
    private readonly ComboBox _benchmarkPaddingComboBox = CreateDropDown();
    private readonly ComboBox _benchmarkKeySizeComboBox = CreateDropDown();
    private readonly NumericUpDown _benchmarkDataSizeNumeric = new() { Minimum = 1, Maximum = 4096, Value = 64, DecimalPlaces = 0, ThousandsSeparator = true, Dock = DockStyle.Fill };
    private readonly NumericUpDown _benchmarkIterationNumeric = new() { Minimum = 1, Maximum = 250, Value = 5, DecimalPlaces = 0, ThousandsSeparator = true, Dock = DockStyle.Fill };
    private readonly TextBox _benchmarkPasswordTextBox = new() { Dock = DockStyle.Fill, UseSystemPasswordChar = true, PlaceholderText = "Password used for key derivation" };
    private readonly CheckBox _benchmarkWarmupCheckBox = new() { Text = "Warm up engines before measuring", AutoSize = true, Checked = true };
    private readonly Button _benchmarkRunButton = new() { Text = "Run benchmark", AutoSize = true };
    private readonly Button _benchmarkCancelButton = new() { Text = "Cancel", AutoSize = true, Enabled = false };
    private readonly Button _benchmarkExportButton = new() { Text = "Export CSV", AutoSize = true, Enabled = false };
    private readonly Button _benchmarkImportButton = new() { Text = "Import CSV", AutoSize = true };
    private readonly ProgressBar _benchmarkProgressBar = new() { Dock = DockStyle.Fill, Visible = false, Style = ProgressBarStyle.Marquee, MarqueeAnimationSpeed = 30, Height = 22 };
    private readonly Label _benchmarkStatusLabel = new() { Dock = DockStyle.Fill, AutoEllipsis = true, Text = "Ready." };
    private readonly DataGridView _benchmarkSummaryGrid = CreateGrid();
    private readonly DataGridView _benchmarkDetailsGrid = CreateGrid();
    private readonly BenchmarkChartControl _benchmarkChart = new() { Dock = DockStyle.Fill };
    private readonly TextBox _benchmarkNotesTextBox = new() { Dock = DockStyle.Fill, ReadOnly = true, Multiline = true, ScrollBars = ScrollBars.Vertical };
    private readonly ComboBox _singleFileOperationComboBox = CreateDropDown();
    private readonly ComboBox _singleFileEngineComboBox = CreateDropDown();
    private readonly ComboBox _singleFileAlgorithmComboBox = CreateDropDown();
    private readonly ComboBox _singleFilePaddingComboBox = CreateDropDown();
    private readonly ComboBox _singleFileKeySizeComboBox = CreateDropDown();
    private readonly TextBox _singleFilePasswordTextBox = new() { Dock = DockStyle.Fill, UseSystemPasswordChar = true, PlaceholderText = "Password" };
    private readonly TextBox _singleFileInputPathTextBox = new() { Dock = DockStyle.Fill, PlaceholderText = "Input file" };
    private readonly TextBox _singleFileOutputPathTextBox = new() { Dock = DockStyle.Fill, PlaceholderText = "Output file" };
    private readonly Button _singleFileBrowseInputButton = new() { Text = "Browse input...", AutoSize = true };
    private readonly Button _singleFileBrowseOutputButton = new() { Text = "Browse output...", AutoSize = true };
    private readonly Button _singleFileRunButton = new() { Text = "Run", AutoSize = true };
    private readonly ProgressBar _singleFileProgressBar = new() { Dock = DockStyle.Fill, Visible = false, Style = ProgressBarStyle.Marquee, MarqueeAnimationSpeed = 30, Height = 22 };
    private readonly Label _singleFileStatusLabel = new() { Dock = DockStyle.Fill, AutoEllipsis = true, Text = "Ready." };
    private readonly TextBox _singleFileInfoTextBox = new() { Dock = DockStyle.Top, Multiline = true, ReadOnly = true, BackColor = Color.White, BorderStyle = BorderStyle.FixedSingle, ScrollBars = ScrollBars.Vertical, Height = 180 };
    private readonly TextBox _diagnosticsTextBox = new() { Dock = DockStyle.Fill, Multiline = true, ScrollBars = ScrollBars.Both, ReadOnly = true, Font = new Font("Consolas", 9f) };

    public Form1()
    {
        _environmentInspectionService = new EnvironmentInspectionService(_nativeCryptoFacade);
        _singleFileCryptoService = new SingleFileCryptoService(_passwordDerivationService, _nativeCryptoFacade);
        _benchmarkService = new BenchmarkService(_passwordDerivationService, _managedCryptoService, _nativeCryptoFacade, _environmentInspectionService);
        InitializeComponent();
        Load += OnFormLoad;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _benchmarkCancellationTokenSource?.Dispose();
        }

        base.Dispose(disposing);
    }

    private void InitializeComponent()
    {
        SuspendLayout();
        AutoScaleMode = AutoScaleMode.Font;
        ClientSize = new Size(1280, 820);
        MinimumSize = new Size(720, 540);
        StartPosition = FormStartPosition.CenterScreen;
        Text = "AES Showcase - WinForms UI";

        Controls.Add(_tabControl);
        BuildSingleFileTab();
        BuildFolderTab();
        BuildBenchmarkTab();
        BuildDiagnosticsTab();

        ResumeLayout(false);
    }

    private void BuildSingleFileTab()
    {
        var page = new TabPage("Single file");
        var root = CreatePageRoot();

        root.Controls.Add(CreateHeaderLabel("Single-file encryption and decryption"), 0, 0);

        _singleFileOperationComboBox.Items.AddRange(new object[] { "Encrypt", "Decrypt" });
        _singleFileOperationComboBox.SelectedIndex = 0;

        _singleFileEngineComboBox.Items.AddRange(new object[] { "Native CPU", "OpenCL" });
        _singleFileEngineComboBox.SelectedIndex = 0;

        _singleFileAlgorithmComboBox.DataSource = Enum.GetValues<CryptoAlgorithm>();
        _singleFilePaddingComboBox.DataSource = Enum.GetValues<CryptoPaddingMode>();
        _singleFileKeySizeComboBox.Items.AddRange(new object[] { "128", "192", "256" });
        _singleFileKeySizeComboBox.SelectedIndex = 2;
        _singleFilePasswordTextBox.Text = "demo-password";
        _singleFileAlgorithmComboBox.SelectedItem = CryptoAlgorithm.Ctr;
        _singleFilePaddingComboBox.SelectedItem = CryptoPaddingMode.Pkcs7;

        _singleFileOperationComboBox.SelectedIndexChanged += (_, _) => SyncSingleFileState();
        _singleFileEngineComboBox.SelectedIndexChanged += (_, _) => SyncSingleFileState();
        _singleFileAlgorithmComboBox.SelectedIndexChanged += (_, _) => SyncSingleFileState();
        _singleFileBrowseInputButton.Click += OnSingleFileBrowseInputClick;
        _singleFileBrowseOutputButton.Click += OnSingleFileBrowseOutputClick;
        _singleFileRunButton.Click += async (_, _) => await RunSingleFileAsync();
        _singleFileInputPathTextBox.TextChanged += (_, _) =>
        {
            if (GetSingleFileOperationIsEncrypt())
            {
                _currentSingleFilePackageInfo = null;
                RefreshSingleFileInfo();
            }
            else
            {
                InspectSingleFilePackage();
                RefreshSingleFileInfo();
            }
        };

        var form = CreateResponsiveFieldTable(2);
        AddLabeledControl(form, 0, 0, "Operation", _singleFileOperationComboBox);
        AddLabeledControl(form, 1, 0, "Engine", _singleFileEngineComboBox);
        AddLabeledControl(form, 0, 1, "Algorithm", _singleFileAlgorithmComboBox);
        AddLabeledControl(form, 1, 1, "Padding", _singleFilePaddingComboBox);
        AddLabeledControl(form, 0, 2, "Key size (bits)", _singleFileKeySizeComboBox);
        AddLabeledControl(form, 1, 2, "Password", _singleFilePasswordTextBox);
        AddLabeledControl(form, 0, 3, "Input file", _singleFileInputPathTextBox);
        AddLabeledControl(form, 1, 3, "Output file", _singleFileOutputPathTextBox);

        var buttonPanel = CreateButtonPanel();
        buttonPanel.Controls.AddRange(new Control[] { _singleFileBrowseInputButton, _singleFileBrowseOutputButton, _singleFileRunButton });

        var statusPanel = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            ColumnCount = 2,
            Margin = new Padding(0, 0, 0, 8)
        };
        statusPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 240f));
        statusPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
        statusPanel.Controls.Add(_singleFileProgressBar, 0, 0);
        statusPanel.Controls.Add(_singleFileStatusLabel, 1, 0);

        root.Controls.Add(form, 0, 1);
        root.Controls.Add(buttonPanel, 0, 2);
        root.Controls.Add(statusPanel, 0, 3);
        root.Controls.Add(_singleFileInfoTextBox, 0, 4);

        page.Controls.Add(CreateScrollableHost(root));
        _tabControl.TabPages.Add(page);

        SyncSingleFileState();
        RefreshSingleFileInfo();
    }

    private async Task RunSingleFileAsync()
    {
        try
        {
            var request = BuildSingleFileRequest();
            ToggleSingleFileUi(isRunning: true);
            _singleFileStatusLabel.Text = request.Encrypt ? "Encrypting file..." : "Decrypting file...";
            var message = await _singleFileCryptoService.ExecuteAsync(request);
            _singleFileStatusLabel.Text = message;
            if (!request.Encrypt)
            {
                var packageResult = _singleFileCryptoService.TryReadPackage(request.InputPath);
                _currentSingleFilePackageInfo = packageResult.Succeeded ? packageResult.Value : null;
            }
        }
        catch (Exception ex)
        {
            _singleFileStatusLabel.Text = "Single-file operation failed.";
            MessageBox.Show(this, ex.Message, "Single-file error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            ToggleSingleFileUi(isRunning: false);
            RefreshDiagnostics();
            RefreshSingleFileInfo();
        }
    }

    private SingleFileRequest BuildSingleFileRequest()
    {
        var encrypt = GetSingleFileOperationIsEncrypt();
        var packageInfo = encrypt ? null : GetSelectedSingleFilePackageOrThrow();
        var algorithm = encrypt ? GetSelectedSingleFileAlgorithm() : packageInfo!.Algorithm;
        var padding = encrypt
            ? (algorithm == CryptoAlgorithm.Gcm ? CryptoPaddingMode.None : GetSelectedSingleFilePadding())
            : packageInfo!.Padding;
        var keySizeBits = encrypt
            ? int.Parse(_singleFileKeySizeComboBox.SelectedItem?.ToString() ?? "256", CultureInfo.InvariantCulture)
            : packageInfo!.KeySizeBits;

        return new SingleFileRequest
        {
            Encrypt = encrypt,
            Engine = GetSelectedSingleFileEngine(),
            Algorithm = algorithm,
            Padding = padding,
            KeySizeBits = keySizeBits,
            Password = _singleFilePasswordTextBox.Text,
            InputPath = _singleFileInputPathTextBox.Text.Trim(),
            OutputPath = _singleFileOutputPathTextBox.Text.Trim()
        };
    }

    private void OnSingleFileBrowseInputClick(object? sender, EventArgs e)
    {
        using var dialog = new OpenFileDialog
        {
            Filter = GetSingleFileOperationIsEncrypt()
                ? "All files (*.*)|*.*"
                : "AES package files (*.aes)|*.aes|All files (*.*)|*.*",
            Multiselect = false
        };

        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }

        _singleFileInputPathTextBox.Text = dialog.FileName;
        if (string.IsNullOrWhiteSpace(_singleFileOutputPathTextBox.Text))
        {
            _singleFileOutputPathTextBox.Text = BuildDefaultSingleFileOutputPath(dialog.FileName, GetSingleFileOperationIsEncrypt());
        }

        InspectSingleFilePackage();
    }

    private void OnSingleFileBrowseOutputClick(object? sender, EventArgs e)
    {
        using var dialog = new SaveFileDialog
        {
            Filter = GetSingleFileOperationIsEncrypt()
                ? "AES package files (*.aes)|*.aes|All files (*.*)|*.*"
                : "All files (*.*)|*.*",
            DefaultExt = GetSingleFileOperationIsEncrypt() ? "aes" : string.Empty,
            FileName = BuildDefaultSingleFileOutputPath(_singleFileInputPathTextBox.Text.Trim(), GetSingleFileOperationIsEncrypt())
        };

        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }

        _singleFileOutputPathTextBox.Text = dialog.FileName;
    }

    private void SyncSingleFileState()
    {
        var encrypt = GetSingleFileOperationIsEncrypt();
        var selectedAlgorithm = GetSelectedSingleFileAlgorithm();
        var packageAlgorithm = _currentSingleFilePackageInfo?.Algorithm;
        var effectiveAlgorithm = encrypt ? selectedAlgorithm : packageAlgorithm ?? selectedAlgorithm;
        var disablePadding = effectiveAlgorithm == CryptoAlgorithm.Gcm;

        if (encrypt)
        {
            _currentSingleFilePackageInfo = null;
        }

        _singleFileAlgorithmComboBox.Enabled = encrypt;
        _singleFilePaddingComboBox.Enabled = encrypt && !disablePadding;
        _singleFileKeySizeComboBox.Enabled = encrypt;
        if (disablePadding)
        {
            _singleFilePaddingComboBox.SelectedItem = CryptoPaddingMode.None;
        }

        if (!encrypt)
        {
            InspectSingleFilePackage();
        }

        RefreshSingleFileInfo();
    }

    private void InspectSingleFilePackage()
    {
        _currentSingleFilePackageInfo = null;
        if (GetSingleFileOperationIsEncrypt())
        {
            return;
        }

        var path = _singleFileInputPathTextBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return;
        }

        var result = _singleFileCryptoService.TryReadPackage(path);
        if (!result.Succeeded || result.Value is null)
        {
            _singleFileStatusLabel.Text = result.Message;
            return;
        }

        _currentSingleFilePackageInfo = result.Value;
        _singleFileAlgorithmComboBox.SelectedItem = result.Value.Algorithm;
        _singleFilePaddingComboBox.SelectedItem = result.Value.Padding;
        _singleFileKeySizeComboBox.SelectedItem = result.Value.KeySizeBits.ToString(CultureInfo.InvariantCulture);
        _singleFileStatusLabel.Text = $"Loaded package metadata: {result.Value.Algorithm}, {result.Value.KeySizeBits}-bit key.";
    }

    private void RefreshSingleFileInfo()
    {
        var lines = new List<string>
        {
            "Single-file mode uses the same native CPU and OpenCL backends as the benchmark tab.",
            "Encrypt mode stores a small metadata header before the ciphertext so decrypt mode can restore the algorithm, padding, salt, IV, and GCM tag automatically.",
            "Decrypt mode uses the package metadata from the input file. Only the selected engine, password, and output path matter there.",
            "CBC and CTR use the native file pipeline when available. GCM falls back to native buffer processing because the native projects expose GCM only as an in-memory API.",
            string.Empty
        };

        if (_currentSingleFilePackageInfo is not null)
        {
            lines.Add("Loaded package metadata:");
            lines.Add($"Algorithm: {_currentSingleFilePackageInfo.Algorithm}");
            lines.Add($"Padding: {_currentSingleFilePackageInfo.Padding}");
            lines.Add($"Key size: {_currentSingleFilePackageInfo.KeySizeBits} bits");
            lines.Add($"PBKDF2 iterations: {_currentSingleFilePackageInfo.IterationCount}");
            lines.Add($"IV length: {_currentSingleFilePackageInfo.Iv.Length} bytes");
            lines.Add($"Tag length: {_currentSingleFilePackageInfo.Tag.Length} bytes");
            lines.Add($"Encrypted payload: {_currentSingleFilePackageInfo.PayloadLength:N0} bytes");
        }
        else
        {
            lines.Add("No encrypted package metadata is currently loaded.");
        }

        var engine = GetSelectedSingleFileEngine();
        var algorithm = _currentSingleFilePackageInfo?.Algorithm ?? GetSelectedSingleFileAlgorithm();
        if (!_nativeCryptoFacade.IsSupported(engine, algorithm))
        {
            lines.Add(string.Empty);
            lines.Add($"The currently selected engine does not support {algorithm}. Switch the engine before running the operation.");
        }

        _singleFileInfoTextBox.Text = string.Join(Environment.NewLine, lines);
    }

    private void ToggleSingleFileUi(bool isRunning)
    {
        _singleFileRunButton.Enabled = !isRunning;
        _singleFileBrowseInputButton.Enabled = !isRunning;
        _singleFileBrowseOutputButton.Enabled = !isRunning;
        _singleFileOperationComboBox.Enabled = !isRunning;
        _singleFileEngineComboBox.Enabled = !isRunning;
        _singleFileAlgorithmComboBox.Enabled = !isRunning && GetSingleFileOperationIsEncrypt();
        _singleFilePaddingComboBox.Enabled = !isRunning && GetSingleFileOperationIsEncrypt() && GetSelectedSingleFileAlgorithm() != CryptoAlgorithm.Gcm;
        _singleFileKeySizeComboBox.Enabled = !isRunning && GetSingleFileOperationIsEncrypt();
        _singleFilePasswordTextBox.Enabled = !isRunning;
        _singleFileInputPathTextBox.Enabled = !isRunning;
        _singleFileOutputPathTextBox.Enabled = !isRunning;
        _singleFileProgressBar.Visible = isRunning;
    }

    private bool GetSingleFileOperationIsEncrypt()
    {
        return string.Equals(_singleFileOperationComboBox.SelectedItem?.ToString(), "Encrypt", StringComparison.OrdinalIgnoreCase);
    }

    private CryptoEngine GetSelectedSingleFileEngine()
    {
        return string.Equals(_singleFileEngineComboBox.SelectedItem?.ToString(), "OpenCL", StringComparison.OrdinalIgnoreCase)
            ? CryptoEngine.OpenCl
            : CryptoEngine.NativeCpu;
    }

    private CryptoAlgorithm GetSelectedSingleFileAlgorithm()
    {
        return _singleFileAlgorithmComboBox.SelectedItem is CryptoAlgorithm algorithm ? algorithm : CryptoAlgorithm.Ctr;
    }

    private CryptoPaddingMode GetSelectedSingleFilePadding()
    {
        return _singleFilePaddingComboBox.SelectedItem is CryptoPaddingMode padding ? padding : CryptoPaddingMode.Pkcs7;
    }

    private SingleFilePackageInfo GetSelectedSingleFilePackageOrThrow()
    {
        InspectSingleFilePackage();
        return _currentSingleFilePackageInfo ?? throw new InvalidOperationException("The selected encrypted input file does not contain a valid AES UI package header.");
    }

    private static string BuildDefaultSingleFileOutputPath(string inputPath, bool encrypt)
    {
        if (string.IsNullOrWhiteSpace(inputPath))
        {
            return string.Empty;
        }

        if (encrypt)
        {
            return inputPath.EndsWith(".aes", StringComparison.OrdinalIgnoreCase) ? inputPath : inputPath + ".aes";
        }

        return inputPath.EndsWith(".aes", StringComparison.OrdinalIgnoreCase)
            ? inputPath[..^4]
            : inputPath + ".dec";
    }

    private void BuildFolderTab()
    {
        var page = new TabPage("Folder processing");
        var root = CreatePageRoot();

        root.Controls.Add(CreateHeaderLabel("Folder-level encryption and decryption"), 0, 0);

        var form = CreateResponsiveFieldTable(2);

        var operationCombo = CreateDropDown();
        operationCombo.Items.AddRange(new object[] { "Encrypt", "Decrypt" });
        operationCombo.SelectedIndex = 0;

        var executionModeCombo = CreateDropDown();
        executionModeCombo.Items.AddRange(new object[]
        {
            "Sequential files + CPU AES",
            "Sequential files + OpenCL AES",
            "File-parallel + CPU AES",
            "File-parallel + OpenCL AES"
        });
        executionModeCombo.SelectedIndex = 0;

        var algorithmCombo = CreateDropDown();
        algorithmCombo.Items.AddRange(new object[] { "CBC", "CTR", "GCM" });
        algorithmCombo.SelectedIndex = 1;

        var paddingCombo = CreateDropDown();
        paddingCombo.Items.AddRange(new object[] { "PKCS7", "ANSI X9.23", "ISO 7816-4", "Zero", "None" });
        paddingCombo.SelectedIndex = 0;

        var keyCombo = CreateDropDown();
        keyCombo.Items.AddRange(new object[] { "128", "192", "256" });
        keyCombo.SelectedIndex = 2;

        var passwordTextBox = new TextBox { Dock = DockStyle.Fill, UseSystemPasswordChar = true, PlaceholderText = "Password" };
        var inputFolderTextBox = new TextBox { Dock = DockStyle.Fill, PlaceholderText = "Input folder" };
        var outputFolderTextBox = new TextBox { Dock = DockStyle.Fill, PlaceholderText = "Output folder" };
        var includeSubfoldersCheckBox = new CheckBox { Text = "Include subfolders", AutoSize = true, Checked = true };

        AddLabeledControl(form, 0, 0, "Operation", operationCombo);
        AddLabeledControl(form, 1, 0, "Execution mode", executionModeCombo);
        AddLabeledControl(form, 0, 1, "Algorithm", algorithmCombo);
        AddLabeledControl(form, 1, 1, "Padding", paddingCombo);
        AddLabeledControl(form, 0, 2, "Key size (bits)", keyCombo);
        AddLabeledControl(form, 1, 2, "Password", passwordTextBox);
        AddLabeledControl(form, 0, 3, "Input folder", inputFolderTextBox);
        AddLabeledControl(form, 1, 3, "Output folder", outputFolderTextBox);

        var buttonPanel = CreateButtonPanel();
        var browseInputButton = new Button { Text = "Browse input folder...", AutoSize = true };
        var browseOutputButton = new Button { Text = "Browse output folder...", AutoSize = true };
        var runButton = new Button { Text = "Run folder job", AutoSize = true };
        browseInputButton.Click += (_, _) => MessageBox.Show(this, "Folder mode needs an additional native batch API for file-level parallelism. The UI scaffold is already in place.", "Planned next", MessageBoxButtons.OK, MessageBoxIcon.Information);
        browseOutputButton.Click += (_, _) => MessageBox.Show(this, "Folder mode needs an additional native batch API for file-level parallelism. The UI scaffold is already in place.", "Planned next", MessageBoxButtons.OK, MessageBoxIcon.Information);
        runButton.Click += (_, _) => MessageBox.Show(this, "Folder processing is prepared in the UI, but the native batch scheduler is not implemented in this revision yet.", "Work in progress", MessageBoxButtons.OK, MessageBoxIcon.Information);
        buttonPanel.Controls.AddRange(new Control[] { browseInputButton, browseOutputButton, runButton, includeSubfoldersCheckBox });

        var infoBox = CreateInfoTextBox("This tab is prepared for the future folder scheduler. The remaining missing piece is a native batch execution API that handles file-level parallelism outside C#.");
        infoBox.Height = 160;

        root.Controls.Add(form, 0, 1);
        root.Controls.Add(buttonPanel, 0, 2);
        root.Controls.Add(infoBox, 0, 3);

        page.Controls.Add(CreateScrollableHost(root));
        _tabControl.TabPages.Add(page);
    }

    private void BuildBenchmarkTab()
    {
        var page = new TabPage("Benchmark");
        var root = CreatePageRoot();

        root.Controls.Add(CreateHeaderLabel("Benchmark native CPU, OpenCL, and managed .NET AES"), 0, 0);

        _benchmarkAlgorithmComboBox.DataSource = Enum.GetValues<CryptoAlgorithm>();
        _benchmarkPaddingComboBox.DataSource = Enum.GetValues<CryptoPaddingMode>();
        _benchmarkKeySizeComboBox.Items.AddRange(new object[] { "128", "192", "256" });
        _benchmarkKeySizeComboBox.SelectedIndex = 2;
        _benchmarkPasswordTextBox.Text = "demo-password";
        _benchmarkAlgorithmComboBox.SelectedItem = CryptoAlgorithm.Ctr;
        _benchmarkPaddingComboBox.SelectedItem = CryptoPaddingMode.Pkcs7;

        _benchmarkAlgorithmComboBox.SelectedIndexChanged += (_, _) => SyncPaddingState();
        _benchmarkRunButton.Click += async (_, _) => await RunBenchmarkAsync();
        _benchmarkCancelButton.Click += (_, _) => _benchmarkCancellationTokenSource?.Cancel();
        _benchmarkExportButton.Click += (_, _) => ExportBenchmarkCsv();
        _benchmarkImportButton.Click += (_, _) => ImportBenchmarkCsv();

        var optionsPanel = CreateResponsiveFieldTable(3);
        AddLabeledControl(optionsPanel, 0, 0, "Algorithm", _benchmarkAlgorithmComboBox);
        AddLabeledControl(optionsPanel, 1, 0, "Padding", _benchmarkPaddingComboBox);
        AddLabeledControl(optionsPanel, 2, 0, "Key size (bits)", _benchmarkKeySizeComboBox);
        AddLabeledControl(optionsPanel, 0, 1, "Data size (MB)", _benchmarkDataSizeNumeric);
        AddLabeledControl(optionsPanel, 1, 1, "Iterations", _benchmarkIterationNumeric);
        AddLabeledControl(optionsPanel, 2, 1, "Password", _benchmarkPasswordTextBox);

        var commandPanel = CreateButtonPanel();
        commandPanel.Controls.AddRange(new Control[]
        {
            _benchmarkRunButton,
            _benchmarkCancelButton,
            _benchmarkExportButton,
            _benchmarkImportButton,
            _benchmarkWarmupCheckBox
        });

        var statusPanel = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            ColumnCount = 1,
            Margin = new Padding(0, 0, 0, 12)
        };
        statusPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
        statusPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        statusPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        statusPanel.Controls.Add(_benchmarkStatusLabel, 0, 0);
        statusPanel.Controls.Add(_benchmarkProgressBar, 0, 1);

        ConfigureSummaryGrid();
        ConfigureDetailsGrid();

        var summarySection = CreateSectionContainer("Summary table", _benchmarkSummaryGrid, 240);
        var chartSection = CreateSectionContainer("Chart", _benchmarkChart, 320);
        var detailsSection = CreateSectionContainer("Per-run details", _benchmarkDetailsGrid, 280);
        var notesSection = CreateSectionContainer("Session notes and metadata", _benchmarkNotesTextBox, 220);

        root.Controls.Add(optionsPanel, 0, 1);
        root.Controls.Add(commandPanel, 0, 2);
        root.Controls.Add(statusPanel, 0, 3);
        root.Controls.Add(summarySection, 0, 4);
        root.Controls.Add(chartSection, 0, 5);
        root.Controls.Add(detailsSection, 0, 6);
        root.Controls.Add(notesSection, 0, 7);

        page.Controls.Add(CreateScrollableHost(root));
        _tabControl.TabPages.Add(page);
        SyncPaddingState();
    }

    private void BuildDiagnosticsTab()
    {
        var page = new TabPage("Diagnostics");
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Padding = new Padding(16) };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
        root.Controls.Add(CreateHeaderLabel("Runtime diagnostics"), 0, 0);

        var refreshButton = new Button { Text = "Refresh diagnostics", AutoSize = true };
        refreshButton.Click += (_, _) => RefreshDiagnostics();
        root.Controls.Add(refreshButton, 0, 1);
        root.Controls.Add(_diagnosticsTextBox, 0, 2);

        page.Controls.Add(root);
        _tabControl.TabPages.Add(page);
    }

    private async void OnFormLoad(object? sender, EventArgs e)
    {
        RefreshDiagnostics();
        await Task.CompletedTask;
    }

    private void SyncPaddingState()
    {
        var algorithm = GetSelectedAlgorithm();
        var isGcm = algorithm == CryptoAlgorithm.Gcm;
        _benchmarkPaddingComboBox.Enabled = !isGcm;
        if (isGcm)
        {
            _benchmarkPaddingComboBox.SelectedItem = CryptoPaddingMode.None;
        }
    }

    private async Task RunBenchmarkAsync()
    {
        try
        {
            var request = BuildBenchmarkRequest();
            ToggleBenchmarkUi(isRunning: true);
            _benchmarkStatusLabel.Text = "Preparing benchmark...";

            _benchmarkCancellationTokenSource?.Dispose();
            _benchmarkCancellationTokenSource = new CancellationTokenSource();
            var progress = new Progress<string>(message => _benchmarkStatusLabel.Text = message);

            var session = await _benchmarkService.RunAsync(request, progress, _benchmarkCancellationTokenSource.Token);
            _currentBenchmarkSession = session;
            PopulateBenchmarkSession(session);
            _benchmarkStatusLabel.Text = $"Completed. {session.Rows.Count(row => row.Succeeded)} successful runs out of {session.Rows.Count}.";
            _benchmarkExportButton.Enabled = true;
        }
        catch (OperationCanceledException)
        {
            _benchmarkStatusLabel.Text = "Benchmark cancelled.";
        }
        catch (Exception ex)
        {
            _benchmarkStatusLabel.Text = "Benchmark failed.";
            MessageBox.Show(this, ex.Message, "Benchmark error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            ToggleBenchmarkUi(isRunning: false);
            RefreshDiagnostics();
        }
    }

    private BenchmarkRequest BuildBenchmarkRequest()
    {
        return new BenchmarkRequest
        {
            Algorithm = GetSelectedAlgorithm(),
            Padding = GetSelectedAlgorithm() == CryptoAlgorithm.Gcm ? CryptoPaddingMode.None : (CryptoPaddingMode)(_benchmarkPaddingComboBox.SelectedItem ?? CryptoPaddingMode.Pkcs7),
            KeySizeBits = int.Parse(_benchmarkKeySizeComboBox.SelectedItem?.ToString() ?? "256", CultureInfo.InvariantCulture),
            DataSizeMegabytes = decimal.ToInt32(_benchmarkDataSizeNumeric.Value),
            IterationCount = decimal.ToInt32(_benchmarkIterationNumeric.Value),
            Password = _benchmarkPasswordTextBox.Text,
            WarmupBeforeRun = _benchmarkWarmupCheckBox.Checked
        };
    }

    private CryptoAlgorithm GetSelectedAlgorithm()
    {
        return _benchmarkAlgorithmComboBox.SelectedItem is CryptoAlgorithm algorithm ? algorithm : CryptoAlgorithm.Ctr;
    }

    private void PopulateBenchmarkSession(BenchmarkSession session)
    {
        PopulateSummaryGrid(session.Summaries);
        PopulateDetailsGrid(session.Rows);
        _benchmarkChart.SetData(session.Summaries);
        _benchmarkNotesTextBox.Text = BuildNotesText(session);
    }

    private void PopulateSummaryGrid(IEnumerable<BenchmarkSummary> summaries)
    {
        _benchmarkSummaryGrid.Rows.Clear();
        foreach (var summary in summaries)
        {
            _benchmarkSummaryGrid.Rows.Add(
                summary.Engine,
                summary.Direction,
                summary.Succeeded ? "Yes" : "No",
                summary.Samples,
                summary.AverageMilliseconds.ToString("F3", CultureInfo.InvariantCulture),
                summary.MedianMilliseconds.ToString("F3", CultureInfo.InvariantCulture),
                summary.BestMilliseconds.ToString("F3", CultureInfo.InvariantCulture),
                summary.AverageThroughputMegabytesPerSecond.ToString("F2", CultureInfo.InvariantCulture),
                summary.BestThroughputMegabytesPerSecond.ToString("F2", CultureInfo.InvariantCulture),
                summary.RelativeSpeedupVsNativeCpu?.ToString("F2", CultureInfo.InvariantCulture) ?? string.Empty,
                summary.Note);
        }

        AutoSizeGridColumns(_benchmarkSummaryGrid);
    }

    private void PopulateDetailsGrid(IEnumerable<BenchmarkResultRow> rows)
    {
        _benchmarkDetailsGrid.Rows.Clear();
        foreach (var row in rows)
        {
            _benchmarkDetailsGrid.Rows.Add(
                row.Iteration,
                row.Engine,
                row.Direction,
                row.Succeeded ? "Yes" : "No",
                row.ElapsedMilliseconds.ToString("F3", CultureInfo.InvariantCulture),
                row.ThroughputMegabytesPerSecond.ToString("F2", CultureInfo.InvariantCulture),
                row.InputBytes,
                row.OutputBytes,
                row.RelativeSpeedupVsNativeCpu?.ToString("F2", CultureInfo.InvariantCulture) ?? string.Empty,
                row.Note);
        }

        AutoSizeGridColumns(_benchmarkDetailsGrid);
    }

    private string BuildNotesText(BenchmarkSession session)
    {
        var successfulSummaries = session.Summaries.Where(summary => summary.Succeeded).OrderByDescending(summary => summary.AverageThroughputMegabytesPerSecond).ToList();
        var winner = successfulSummaries.FirstOrDefault();
        var lines = new List<string>
        {
            $"Session: {session.SessionId}",
            $"Created (UTC): {session.CreatedUtc:O}",
            $"Algorithm: {session.Request.Algorithm}",
            $"Padding: {(session.Request.Algorithm == CryptoAlgorithm.Gcm ? "N/A" : session.Request.Padding.ToString())}",
            $"Key size: {session.Request.KeySizeBits} bits",
            $"Data size: {session.Request.DataSizeMegabytes} MB",
            $"Iterations: {session.Request.IterationCount}",
            $"Warmup enabled: {session.Request.WarmupBeforeRun}",
            $"Password: {session.Request.Password}",
            $"Salt (Base64): {session.SaltBase64}",
            $"IV16 (Base64): {session.Iv16Base64}",
            $"IV12 (Base64): {session.Iv12Base64}",
            $"AAD (Base64): {session.AadBase64}",
            $"Environment: {session.EnvironmentDescription}",
            string.Empty,
            $"Best average throughput: {(winner is null ? "No successful result" : $"{winner.Engine} {winner.Direction} at {winner.AverageThroughputMegabytesPerSecond:F2} MB/s")}",
            "Speed-up values in this view compare only the OpenCL-parallel AES against the native sequential AES baseline.",
            "Managed .NET AES is included as an informational reference and is not used as the speed-up baseline.",
            session.Notes
        };

        return string.Join(Environment.NewLine, lines);
    }

    private void ExportBenchmarkCsv()
    {
        if (_currentBenchmarkSession is null)
        {
            MessageBox.Show(this, "There is no benchmark session to export yet.", "Nothing to export", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        using var dialog = new SaveFileDialog
        {
            Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*",
            DefaultExt = "csv",
            FileName = $"aes-benchmark-{_currentBenchmarkSession.CreatedUtc:yyyyMMdd-HHmmss}.csv"
        };

        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }

        File.WriteAllText(dialog.FileName, _benchmarkCsvService.CreateCsv(_currentBenchmarkSession));
        _benchmarkStatusLabel.Text = $"Exported benchmark CSV to {dialog.FileName}.";
    }

    private void ImportBenchmarkCsv()
    {
        using var dialog = new OpenFileDialog
        {
            Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*",
            Multiselect = false
        };

        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }

        try
        {
            var session = _benchmarkCsvService.ParseCsv(File.ReadAllText(dialog.FileName));
            _currentBenchmarkSession = session;
            ApplySessionToBenchmarkInputs(session);
            PopulateBenchmarkSession(session);
            _benchmarkExportButton.Enabled = true;
            _benchmarkStatusLabel.Text = $"Imported benchmark CSV from {dialog.FileName}.";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Import error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void ApplySessionToBenchmarkInputs(BenchmarkSession session)
    {
        _benchmarkAlgorithmComboBox.SelectedItem = session.Request.Algorithm;
        _benchmarkPaddingComboBox.SelectedItem = session.Request.Algorithm == CryptoAlgorithm.Gcm ? CryptoPaddingMode.None : session.Request.Padding;
        _benchmarkKeySizeComboBox.SelectedItem = session.Request.KeySizeBits.ToString(CultureInfo.InvariantCulture);
        _benchmarkDataSizeNumeric.Value = Math.Clamp(session.Request.DataSizeMegabytes, (int)_benchmarkDataSizeNumeric.Minimum, (int)_benchmarkDataSizeNumeric.Maximum);
        _benchmarkIterationNumeric.Value = Math.Clamp(session.Request.IterationCount, (int)_benchmarkIterationNumeric.Minimum, (int)_benchmarkIterationNumeric.Maximum);
        _benchmarkPasswordTextBox.Text = session.Request.Password;
        _benchmarkWarmupCheckBox.Checked = session.Request.WarmupBeforeRun;
        SyncPaddingState();
    }

    private void ToggleBenchmarkUi(bool isRunning)
    {
        _benchmarkRunButton.Enabled = !isRunning;
        _benchmarkCancelButton.Enabled = isRunning;
        _benchmarkImportButton.Enabled = !isRunning;
        _benchmarkExportButton.Enabled = !isRunning && _currentBenchmarkSession is not null;
        _benchmarkAlgorithmComboBox.Enabled = !isRunning;
        _benchmarkPaddingComboBox.Enabled = !isRunning && GetSelectedAlgorithm() != CryptoAlgorithm.Gcm;
        _benchmarkKeySizeComboBox.Enabled = !isRunning;
        _benchmarkDataSizeNumeric.Enabled = !isRunning;
        _benchmarkIterationNumeric.Enabled = !isRunning;
        _benchmarkPasswordTextBox.Enabled = !isRunning;
        _benchmarkWarmupCheckBox.Enabled = !isRunning;
        _benchmarkProgressBar.Visible = isRunning;
    }

    private void RefreshDiagnostics()
    {
        _diagnosticsTextBox.Text = _environmentInspectionService.BuildDiagnosticsReport();
    }

    private static TableLayoutPanel CreatePageRoot()
    {
        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            ColumnCount = 1,
            Padding = new Padding(16)
        };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
        return root;
    }

    private static Panel CreateScrollableHost(Control content)
    {
        var host = new Panel { Dock = DockStyle.Fill, AutoScroll = true };
        host.Controls.Add(content);
        return host;
    }

    private static TableLayoutPanel CreateResponsiveFieldTable(int columnCount)
    {
        var panel = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            ColumnCount = columnCount,
            Margin = new Padding(0, 0, 0, 12)
        };

        for (var column = 0; column < columnCount; column++)
        {
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f / columnCount));
        }

        return panel;
    }

    private static FlowLayoutPanel CreateButtonPanel()
    {
        return new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            WrapContents = true,
            FlowDirection = FlowDirection.LeftToRight,
            Margin = new Padding(0, 0, 0, 8)
        };
    }

    private static Panel CreateSectionContainer(string title, Control body, int bodyHeight)
    {
        var container = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            ColumnCount = 1,
            RowCount = 2,
            Height = bodyHeight + 42,
            Margin = new Padding(0, 0, 0, 12),
            Padding = new Padding(0)
        };
        container.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
        container.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        container.RowStyles.Add(new RowStyle(SizeType.Absolute, bodyHeight));
        container.Controls.Add(CreateSectionLabel(title), 0, 0);
        container.Controls.Add(body, 0, 1);
        return container;
    }

    private static Label CreateHeaderLabel(string text)
    {
        return new Label
        {
            Text = text,
            AutoSize = true,
            Font = new Font(SystemFonts.MessageBoxFont.FontFamily, 15f, FontStyle.Bold),
            Margin = new Padding(0, 0, 0, 12)
        };
    }

    private static Label CreateSectionLabel(string text)
    {
        return new Label
        {
            Text = text,
            AutoSize = true,
            Font = new Font(SystemFonts.MessageBoxFont.FontFamily, 10.5f, FontStyle.Bold),
            Margin = new Padding(0, 0, 0, 8)
        };
    }

    private static ComboBox CreateDropDown()
    {
        return new ComboBox { Dock = DockStyle.Fill, DropDownStyle = ComboBoxStyle.DropDownList };
    }

    private static DataGridView CreateGrid()
    {
        return new DataGridView
        {
            Dock = DockStyle.Fill,
            AllowUserToAddRows = false,
            AllowUserToDeleteRows = false,
            AllowUserToResizeRows = false,
            ReadOnly = true,
            MultiSelect = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            RowHeadersVisible = false,
            AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.AllCells,
            BackgroundColor = Color.White,
            BorderStyle = BorderStyle.FixedSingle
        };
    }

    private static TextBox CreateInfoTextBox(string text)
    {
        return new TextBox
        {
            Dock = DockStyle.Top,
            Multiline = true,
            ReadOnly = true,
            Text = text,
            BackColor = Color.White,
            BorderStyle = BorderStyle.FixedSingle,
            ScrollBars = ScrollBars.Vertical
        };
    }

    private static void AddLabeledControl(TableLayoutPanel panel, int column, int row, string labelText, Control control)
    {
        while (panel.RowCount <= row * 2 + 1)
        {
            panel.RowCount++;
            panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        }

        control.Margin = new Padding(0, 0, 12, 0);
        var label = new Label { Text = labelText, AutoSize = true, Margin = new Padding(0, 8, 12, 4) };
        panel.Controls.Add(label, column, row * 2);
        panel.Controls.Add(control, column, row * 2 + 1);
    }

    private void ConfigureSummaryGrid()
    {
        _benchmarkSummaryGrid.Columns.Clear();
        _benchmarkSummaryGrid.Columns.Add("Engine", "Engine");
        _benchmarkSummaryGrid.Columns.Add("Direction", "Direction");
        _benchmarkSummaryGrid.Columns.Add("Succeeded", "Succeeded");
        _benchmarkSummaryGrid.Columns.Add("Samples", "Samples");
        _benchmarkSummaryGrid.Columns.Add("AverageMs", "Average ms");
        _benchmarkSummaryGrid.Columns.Add("MedianMs", "Median ms");
        _benchmarkSummaryGrid.Columns.Add("BestMs", "Best ms");
        _benchmarkSummaryGrid.Columns.Add("AverageMbps", "Average MB/s");
        _benchmarkSummaryGrid.Columns.Add("BestMbps", "Best MB/s");
        _benchmarkSummaryGrid.Columns.Add("SpeedupCpu", "Speed-up vs sequential native AES");
        _benchmarkSummaryGrid.Columns.Add("Note", "Note");
    }

    private void ConfigureDetailsGrid()
    {
        _benchmarkDetailsGrid.Columns.Clear();
        _benchmarkDetailsGrid.Columns.Add("Iteration", "Iteration");
        _benchmarkDetailsGrid.Columns.Add("Engine", "Engine");
        _benchmarkDetailsGrid.Columns.Add("Direction", "Direction");
        _benchmarkDetailsGrid.Columns.Add("Succeeded", "Succeeded");
        _benchmarkDetailsGrid.Columns.Add("ElapsedMs", "Elapsed ms");
        _benchmarkDetailsGrid.Columns.Add("Throughput", "MB/s");
        _benchmarkDetailsGrid.Columns.Add("InputBytes", "Input bytes");
        _benchmarkDetailsGrid.Columns.Add("OutputBytes", "Output bytes");
        _benchmarkDetailsGrid.Columns.Add("SpeedupCpu", "Speed-up vs sequential native AES");
        _benchmarkDetailsGrid.Columns.Add("Note", "Note");
    }

    private static void AutoSizeGridColumns(DataGridView grid)
    {
        foreach (DataGridViewColumn column in grid.Columns)
        {
            column.AutoSizeMode = column.Name == "Note" ? DataGridViewAutoSizeColumnMode.Fill : DataGridViewAutoSizeColumnMode.AllCells;
        }
    }
}
