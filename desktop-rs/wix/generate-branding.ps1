param(
    [string]$OutDir = $PSScriptRoot
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing

if (-not (Test-Path -LiteralPath $OutDir)) {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
}

function Save-Bmp24 {
    param(
        [System.Drawing.Bitmap]$Bitmap,
        [string]$Path
    )
    $Bitmap.Save($Path, [System.Drawing.Imaging.ImageFormat]::Bmp)
}

function Draw-Bolt {
    param(
        [System.Drawing.Graphics]$Graphics,
        [float]$Cx,
        [float]$Cy,
        [float]$Scale,
        [System.Drawing.Color]$Color
    )
    $pts = [System.Drawing.PointF[]]@(
        [System.Drawing.PointF]::new($Cx + 2.0 * $Scale, $Cy - 11.0 * $Scale),
        [System.Drawing.PointF]::new($Cx - 6.5 * $Scale, $Cy + 1.0 * $Scale),
        [System.Drawing.PointF]::new($Cx - 0.5 * $Scale, $Cy + 1.0 * $Scale),
        [System.Drawing.PointF]::new($Cx - 2.0 * $Scale, $Cy + 11.0 * $Scale),
        [System.Drawing.PointF]::new($Cx + 6.5 * $Scale, $Cy - 1.0 * $Scale),
        [System.Drawing.PointF]::new($Cx + 0.5 * $Scale, $Cy - 1.0 * $Scale)
    )
    $brush = [System.Drawing.SolidBrush]::new($Color)
    try {
        $Graphics.FillPolygon($brush, $pts)
    } finally {
        $brush.Dispose()
    }
}

$bgDark   = [System.Drawing.Color]::FromArgb(0x14, 0x14, 0x18)
$bgTile   = [System.Drawing.Color]::FromArgb(0x1E, 0x1E, 0x24)
$bgLight  = [System.Drawing.Color]::FromArgb(0xF8, 0xF8, 0xFA)
$accent   = [System.Drawing.Color]::FromArgb(0xB9, 0xA8, 0xFF)
$borderLt = [System.Drawing.Color]::FromArgb(0xE4, 0xE4, 0xE8)
$borderDk = [System.Drawing.Color]::FromArgb(0x2E, 0x2E, 0x36)
$txtLight = [System.Drawing.Color]::FromArgb(0xF2, 0xF2, 0xF5)
$txtMute  = [System.Drawing.Color]::FromArgb(0x9A, 0x9A, 0xA6)

# 1. Dialog background: 493x312 (left branding strip 0..164px, right light area 164..493px)
$dialogBmp = [System.Drawing.Bitmap]::new(493, 312, [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
$g = [System.Drawing.Graphics]::FromImage($dialogBmp)
try {
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit

    $bDark  = [System.Drawing.SolidBrush]::new($bgDark)
    $bTile  = [System.Drawing.SolidBrush]::new($bgTile)
    $bLight = [System.Drawing.SolidBrush]::new($bgLight)
    $bAcc   = [System.Drawing.SolidBrush]::new($accent)
    $pBord  = [System.Drawing.Pen]::new($borderDk, 1.0)
    $bTitle = [System.Drawing.SolidBrush]::new($txtLight)
    $bSub   = [System.Drawing.SolidBrush]::new($txtMute)

    $g.FillRectangle($bLight, 0, 0, 493, 312)
    $g.FillRectangle($bDark, 0, 0, 164, 312)
    $g.FillRectangle($bAcc, 162, 0, 2, 312)

    # Rounded square badge
    $badgeRect = [System.Drawing.Rectangle]::new(24, 28, 44, 44)
    $g.FillRectangle($bTile, $badgeRect)
    $g.DrawRectangle($pBord, $badgeRect)
    Draw-Bolt -Graphics $g -Cx 46.0 -Cy 50.0 -Scale 1.25 -Color $accent

    $fontTitle = [System.Drawing.Font]::new("Segoe UI", 16.0, [System.Drawing.FontStyle]::Bold)
    $fontSub   = [System.Drawing.Font]::new("Segoe UI", 8.5, [System.Drawing.FontStyle]::Regular)
    $g.DrawString("Tachyon", $fontTitle, $bTitle, 22.0, 86.0)
    $g.DrawString("Сетевой движок", $fontSub, $bSub, 24.0, 118.0)
    $g.DrawString("и туннелирование", $fontSub, $bSub, 24.0, 134.0)

    # Subtle bottom grid lines on branding panel (4px rhythm)
    for ($y = 264; $y -le 288; $y += 8) {
        $g.DrawLine($pBord, 24, $y, 136, $y)
    }
    $g.FillRectangle($bAcc, 24, 296, 36, 2)

    $fontTitle.Dispose()
    $fontSub.Dispose()
    $bDark.Dispose()
    $bTile.Dispose()
    $bLight.Dispose()
    $bAcc.Dispose()
    $pBord.Dispose()
    $bTitle.Dispose()
    $bSub.Dispose()
} finally {
    $g.Dispose()
}
Save-Bmp24 -Bitmap $dialogBmp -Path (Join-Path $OutDir "dialog.bmp")
$dialogBmp.Dispose()

# 2. Banner: 493x58 (light top header + dark tile 435..493px with bolt)
$bannerBmp = [System.Drawing.Bitmap]::new(493, 58, [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
$gb = [System.Drawing.Graphics]::FromImage($bannerBmp)
try {
    $gb.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias

    $bLight = [System.Drawing.SolidBrush]::new($bgLight)
    $bDark  = [System.Drawing.SolidBrush]::new($bgDark)
    $bAcc   = [System.Drawing.SolidBrush]::new($accent)
    $pLine  = [System.Drawing.Pen]::new($borderLt, 1.0)

    $gb.FillRectangle($bLight, 0, 0, 493, 58)
    $gb.FillRectangle($bDark, 435, 0, 58, 58)
    $gb.FillRectangle($bAcc, 435, 0, 2, 58)
    $gb.DrawLine($pLine, 0, 57, 435, 57)

    Draw-Bolt -Graphics $gb -Cx 464.0 -Cy 29.0 -Scale 1.2 -Color $accent

    $bLight.Dispose()
    $bDark.Dispose()
    $bAcc.Dispose()
    $pLine.Dispose()
} finally {
    $gb.Dispose()
}
Save-Bmp24 -Bitmap $bannerBmp -Path (Join-Path $OutDir "banner.bmp")
$bannerBmp.Dispose()

Write-Host "Generated banner.bmp and dialog.bmp in $OutDir"
