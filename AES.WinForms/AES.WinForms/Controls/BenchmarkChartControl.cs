using System.Drawing.Drawing2D;
using AES.WinForms.Models;

namespace AES.WinForms.Controls;

public sealed class BenchmarkChartControl : Control
{
    private IReadOnlyList<BenchmarkSummary> _summaries = Array.Empty<BenchmarkSummary>();

    public BenchmarkChartControl()
    {
        DoubleBuffered = true;
        ResizeRedraw = true;
        BackColor = Color.White;
    }

    public void SetData(IReadOnlyList<BenchmarkSummary> summaries)
    {
        _summaries = summaries.Where(summary => summary.Succeeded).ToList();
        Invalidate();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);

        var graphics = e.Graphics;
        graphics.SmoothingMode = SmoothingMode.AntiAlias;
        graphics.Clear(BackColor);

        var bounds = Rectangle.Inflate(ClientRectangle, -12, -12);
        if (bounds.Width < 180 || bounds.Height < 140)
        {
            DrawCenteredMessage(graphics, bounds, "Resize the chart area to see benchmark results.");
            return;
        }

        using var borderPen = new Pen(Color.Gainsboro, 1f);
        graphics.DrawRectangle(borderPen, bounds);

        if (_summaries.Count == 0)
        {
            DrawCenteredMessage(graphics, bounds, "No benchmark results available yet.");
            return;
        }

        var titleFontSize = bounds.Width >= 640 ? 10f : bounds.Width >= 440 ? 9f : 8f;
        var valueFontSize = bounds.Width >= 640 ? 8.5f : 7.5f;
        var labelFontSize = bounds.Width >= 640 ? 8f : 7f;

        using var titleFont = new Font(Font.FontFamily, titleFontSize, FontStyle.Bold);
        using var valueFont = new Font(Font.FontFamily, valueFontSize, FontStyle.Regular);
        using var labelFont = new Font(Font.FontFamily, labelFontSize, FontStyle.Regular);
        using var titleBrush = new SolidBrush(Color.FromArgb(36, 36, 36));
        using var textBrush = new SolidBrush(Color.FromArgb(48, 48, 48));
        using var gridPen = new Pen(Color.FromArgb(230, 230, 230), 1f);
        using var axisPen = new Pen(Color.Gray, 1f);
        using var managedBrush = new SolidBrush(Color.FromArgb(94, 129, 172));
        using var nativeBrush = new SolidBrush(Color.FromArgb(163, 190, 140));
        using var openClBrush = new SolidBrush(Color.FromArgb(208, 135, 112));

        var titleText = "Average throughput by engine and direction (MB/s)";
        var titleHeight = TextRenderer.MeasureText(graphics, titleText, titleFont, new Size(bounds.Width - 16, 0), TextFormatFlags.WordBreak).Height;
        var topMargin = bounds.Top + 8;
        TextRenderer.DrawText(graphics, titleText, titleFont, new Rectangle(bounds.Left + 8, topMargin, bounds.Width - 16, titleHeight), titleBrush.Color, TextFormatFlags.WordBreak);

        var maxValue = Math.Max(1d, _summaries.Max(summary => summary.AverageThroughputMegabytesPerSecond));
        var tickLabel = maxValue.ToString("F0");
        var tickLabelWidth = TextRenderer.MeasureText(graphics, tickLabel, valueFont).Width;
        var leftMargin = bounds.Left + Math.Max(36, tickLabelWidth + 12);
        var rightMargin = bounds.Right - 12;
        var bottomLabelHeight = bounds.Width >= 540 ? 42 : 54;
        var plotTop = topMargin + titleHeight + 8;
        var plotBottom = bounds.Bottom - bottomLabelHeight - 8;
        var plotWidth = Math.Max(80, rightMargin - leftMargin);
        var plotHeight = Math.Max(60, plotBottom - plotTop);
        var plotArea = new Rectangle(leftMargin, plotTop, plotWidth, plotHeight);
        var axisY = plotArea.Bottom;
        var axisX = plotArea.Left;

        graphics.DrawLine(axisPen, axisX, plotArea.Top, axisX, axisY);
        graphics.DrawLine(axisPen, axisX, axisY, plotArea.Right, axisY);

        for (var tick = 1; tick <= 5; tick++)
        {
            var ratio = tick / 5f;
            var y = axisY - (int)(plotArea.Height * ratio);
            graphics.DrawLine(gridPen, axisX, y, plotArea.Right, y);
            var currentTickLabel = (maxValue * ratio).ToString("F0");
            var tickSize = TextRenderer.MeasureText(graphics, currentTickLabel, valueFont);
            TextRenderer.DrawText(graphics, currentTickLabel, valueFont, new Point(axisX - tickSize.Width - 6, y - (tickSize.Height / 2)), textBrush.Color);
        }

        var count = _summaries.Count;
        var spacing = Math.Max(6f, Math.Min(18f, plotArea.Width / (float)(count * 5)));
        var totalSpacing = spacing * (count + 1);
        var barWidth = Math.Max(12f, (plotArea.Width - totalSpacing) / count);
        var maxBarWidth = Math.Max(12f, plotArea.Width / (float)Math.Max(count * 2, 1));
        barWidth = Math.Min(barWidth, maxBarWidth);
        var usedWidth = (barWidth * count) + (spacing * (count + 1));
        var startX = plotArea.Left + Math.Max(0f, (plotArea.Width - usedWidth) / 2f) + spacing;

        using var labelFormat = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Near };

        for (var index = 0; index < count; index++)
        {
            var summary = _summaries[index];
            var heightRatio = (float)(summary.AverageThroughputMegabytesPerSecond / maxValue);
            var barHeight = Math.Max(2f, plotArea.Height * heightRatio);
            var x = startX + index * (barWidth + spacing);
            var y = axisY - barHeight;
            var barRectangle = new RectangleF(x, y, barWidth, barHeight);
            graphics.FillRectangle(GetBrush(summary.Engine, nativeBrush, openClBrush, managedBrush), barRectangle);

            if (plotArea.Width >= 220)
            {
                var valueLabel = summary.AverageThroughputMegabytesPerSecond.ToString("F1");
                var valueSize = TextRenderer.MeasureText(graphics, valueLabel, valueFont);
                var valueX = (int)(x + ((barWidth - valueSize.Width) / 2f));
                var valueY = (int)Math.Max(bounds.Top + 4, y - valueSize.Height - 2f);
                TextRenderer.DrawText(graphics, valueLabel, valueFont, new Point(valueX, valueY), textBrush.Color);
            }

            var labelRect = new RectangleF(x - (spacing / 2f), axisY + 6f, barWidth + spacing, bottomLabelHeight - 8f);
            graphics.DrawString(BuildSummaryLabel(summary), labelFont, textBrush, labelRect, labelFormat);
        }
    }

    private void DrawCenteredMessage(Graphics graphics, Rectangle bounds, string message)
    {
        using var brush = new SolidBrush(Color.DimGray);
        using var font = new Font(Font.FontFamily, 9f, FontStyle.Regular);
        var size = TextRenderer.MeasureText(graphics, message, font);
        var x = bounds.Left + Math.Max(0, (bounds.Width - size.Width) / 2);
        var y = bounds.Top + Math.Max(0, (bounds.Height - size.Height) / 2);
        TextRenderer.DrawText(graphics, message, font, new Point(x, y), brush.Color);
    }

    private static string BuildSummaryLabel(BenchmarkSummary summary)
    {
        var engine = summary.Engine switch
        {
            CryptoEngine.NativeCpu => "CPU",
            CryptoEngine.OpenCl => "OpenCL",
            _ => "Managed"
        };

        return $"{engine}\n{summary.Direction}";
    }

    private static Brush GetBrush(CryptoEngine engine, Brush nativeBrush, Brush openClBrush, Brush managedBrush)
    {
        return engine switch
        {
            CryptoEngine.NativeCpu => nativeBrush,
            CryptoEngine.OpenCl => openClBrush,
            _ => managedBrush
        };
    }
}
