<#
Purview-Case-Tools_v8
#>
[CmdletBinding()]
param()

# ------------------ Utilities & Setup ------------------
$ErrorActionPreference = 'Stop'
$logDir = 'C:\PurviewCaseToolLogs'
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }
$logFile = Join-Path $logDir ("PurviewTools_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
$SettingsPath = Join-Path $env:APPDATA 'PurviewCaseTools\settings.json'

# State shared between the UI thread and the background worker runspace
$OutQueue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
$Shared   = [hashtable]::Synchronized(@{ IsConnected = $false; Account = $null; Tenant = $null; Progress = $null })

# Functions used by the actions. They are loaded here and into the worker runspace,
# where every Security & Compliance cmdlet runs so the window stays responsive.
$WorkerFunctions = {
    Function Write-Log {
        param([string]$Message, [string]$Level = 'INFO')
        $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
        $line | Tee-Object -FilePath $logFile -Append | Out-Null
    }

    # Log one outcome and queue it as a row for the active page's results grid
    Function Write-Result {
        param(
            [string]$Case,
            [string]$Member,
            [string]$Action,
            [ValidateSet('Success','Failed','Skipped','Info')][string]$Result,
            [string]$Detail
        )
        $level = if ($Result -eq 'Failed') { 'ERROR' } else { 'INFO' }
        Write-Log ("{0} | case '{1}' | member '{2}' | {3} | {4}" -f $Action, $Case, $Member, $Result, $Detail) $level
        $OutQueue.Enqueue([pscustomobject]@{
            Time   = Get-Date -Format 'HH:mm:ss'
            Case   = $Case
            Member = $Member
            Action = $Action
            Result = $Result
            Detail = $Detail
        })
    }

    # Report how far the current action has got; the status bar shows it as a progress bar
    Function Set-ActionProgress {
        param([int]$Done, [int]$Total, [string]$Unit = 'cases')
        $Shared.Progress = [pscustomobject]@{ Done = $Done; Total = $Total; Unit = $Unit }
    }

    Function Ensure-Modules {
        if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
            Write-Log "ExchangeOnlineManagement not found; attempting install..." "WARN"
            Install-Module ExchangeOnlineManagement -Scope AllUsers -Force -ErrorAction Stop
        }
    }

    # The Security & Compliance connection, or $null when this module version cannot report it
    Function Get-IppsConnection {
        if (-not (Get-Command Get-ConnectionInformation -ErrorAction SilentlyContinue)) { return $null }
        Get-ConnectionInformation -ErrorAction SilentlyContinue |
            Where-Object { $_.IsEopSession -or ($_.ConnectionUri -match 'compliance') } |
            Select-Object -First 1
    }

    Function Connect-Compliance {
        if ($Shared.IsConnected) {
            # Older module versions have no Get-ConnectionInformation; trust the flag there
            if (-not (Get-Command Get-ConnectionInformation -ErrorAction SilentlyContinue)) { return }
            $conn = Get-IppsConnection
            if ($conn -and $conn.State -eq 'Connected' -and $conn.TokenStatus -ne 'Expired') { return }
            Write-Log "Security & Compliance session expired or was lost; reconnecting." "WARN"
            $Shared.IsConnected = $false
            $Shared.Account = $null
            $Shared.Tenant = $null
        }
        Ensure-Modules
        Import-Module ExchangeOnlineManagement -ErrorAction Stop
        Write-Log "Connecting to Security & Compliance (IPPS Session)..."
        try {
            Connect-IPPSSession -ErrorAction Stop | Out-Null
            $conn = Get-IppsConnection
            if ($conn) {
                $Shared.Account = [string]$conn.UserPrincipalName
                $Shared.Tenant  = [string]$conn.TenantID
            }
            $Shared.IsConnected = $true
            Write-Log ("Connected as {0} (tenant {1})." -f $Shared.Account, $Shared.Tenant)
        }
        catch {
            Write-Log ("Failed to connect: {0}" -f $_.Exception.Message) "ERROR"
            throw
        }
    }

    Function Get-CaseMemberEmails {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory=$true)][string]$Case,
            [string]$ExcludeEmail
        )

        try {
            $members = Get-ComplianceCaseMember -Case $Case -ErrorAction Stop

            $emails = $members | ForEach-Object {
                $addr = $_.PrimarySmtpAddress
                if ([string]::IsNullOrWhiteSpace($addr)) { $addr = $_.Name }
                if ($addr) { $addr.Trim() }
            } | Where-Object { $_ } | Select-Object -Unique

            if ($ExcludeEmail) {
                $emails = $emails | Where-Object { $_ -ine $ExcludeEmail }
            }

            return $emails
        }
        catch {
            $msg = "Failed to get members for case '$Case': $($_.Exception.Message)"
            Write-Log $msg 'ERROR'
            throw $msg
        }
    }

    # Case names can contain characters that are not allowed in file names
    Function ConvertTo-SafeFileName {
        param([string]$Name)
        $pattern = '[{0}]' -f [regex]::Escape(-join [System.IO.Path]::GetInvalidFileNameChars())
        ($Name -replace $pattern, '_').Trim()
    }
}
. $WorkerFunctions

# ------------------ Input parsing ------------------
$EmailPattern = '^[^@\s]+@[^@\s]+\.[^@\s]+$'

# Splits a box's text on commas, semicolons and new lines into trimmed, non-empty entries
Function Split-InputList {
    param([string]$Text)
    @(($Text -split "[`,;\r\n]") | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

# Entries that are not valid email addresses are skipped (the page flags them as you type)
Function Parse-Emails {
    param([string]$EmailsMultiline)
    Split-InputList $EmailsMultiline |
        Where-Object { $_ -match $EmailPattern } |
        Select-Object -Unique
}

Function Parse-Cases {
    param([string]$CasesMultiline)
    Split-InputList $CasesMultiline |
        Select-Object -Unique
}

# ------------------ WPF UI ------------------
Add-Type -AssemblyName PresentationCore, PresentationFramework | Out-Null

# Shared styles for the main window and the case picker. Colours are DynamicResource keys
# that Set-Theme fills in, so switching between light and dark updates everything in place.
$ThemeXaml = @'
    <!-- Text -->
    <Style x:Key="PageTitle" TargetType="TextBlock">
      <Setter Property="FontSize" Value="22"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Foreground" Value="{DynamicResource TextPrimary}"/>
    </Style>
    <Style x:Key="PageSubtitle" TargetType="TextBlock">
      <Setter Property="Foreground" Value="{DynamicResource TextSecondary}"/>
      <Setter Property="Margin" Value="0,4,0,0"/>
      <Setter Property="TextWrapping" Value="Wrap"/>
    </Style>
    <Style x:Key="SectionTitle" TargetType="TextBlock">
      <Setter Property="FontSize" Value="14"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Foreground" Value="{DynamicResource TextPrimary}"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
    </Style>
    <Style x:Key="FieldLabel" TargetType="TextBlock">
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="TextWrapping" Value="Wrap"/>
      <Setter Property="Foreground" Value="{DynamicResource TextPrimary}"/>
      <Setter Property="Margin" Value="0,0,0,6"/>
    </Style>
    <Style x:Key="Hint" TargetType="TextBlock">
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="Foreground" Value="{DynamicResource TextSecondary}"/>
      <Setter Property="Margin" Value="0,6,0,0"/>
      <Setter Property="TextWrapping" Value="Wrap"/>
    </Style>
    <Style x:Key="CellText" TargetType="TextBlock">
      <Setter Property="TextTrimming" Value="CharacterEllipsis"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
      <Setter Property="ToolTip" Value="{Binding Text, RelativeSource={RelativeSource Self}}"/>
      <Style.Triggers>
        <Trigger Property="Text" Value="">
          <Setter Property="ToolTip" Value="{x:Null}"/>
        </Trigger>
      </Style.Triggers>
    </Style>

    <!-- Dotted focus rectangle, shown only when focus arrives from the keyboard -->
    <Style x:Key="KeyboardFocus">
      <Setter Property="Control.Template">
        <Setter.Value>
          <ControlTemplate>
            <Rectangle Margin="1" Stroke="{DynamicResource FocusBorder}" StrokeThickness="1" StrokeDashArray="1 2" SnapsToDevicePixels="True"/>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- Card panels -->
    <Style x:Key="Card" TargetType="Border">
      <Setter Property="Background" Value="{DynamicResource CardBg}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource CardBorder}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="CornerRadius" Value="8"/>
      <Setter Property="Padding" Value="16"/>
      <Setter Property="Margin" Value="0,0,0,16"/>
    </Style>

    <!-- Buttons: Tag holds an optional icon glyph shown before the text -->
    <Style TargetType="Button">
      <Setter Property="Background" Value="{DynamicResource ButtonBg}"/>
      <Setter Property="Foreground" Value="{DynamicResource TextPrimary}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource ButtonBorder}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="14,7"/>
      <Setter Property="HorizontalContentAlignment" Value="Center"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Bd" CornerRadius="6" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" SnapsToDevicePixels="True">
              <Grid>
                <Border x:Name="Overlay" CornerRadius="5" Background="{DynamicResource HoverOverlay}" Opacity="0"/>
                <StackPanel Orientation="Horizontal" Margin="{TemplateBinding Padding}" HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}" VerticalAlignment="Center">
                  <TextBlock x:Name="Icon" Text="{Binding Tag, RelativeSource={RelativeSource TemplatedParent}}" FontFamily="Segoe Fluent Icons, Segoe MDL2 Assets" FontSize="14" Margin="0,0,8,0" VerticalAlignment="Center"/>
                  <ContentPresenter VerticalAlignment="Center" RecognizesAccessKey="True"/>
                </StackPanel>
              </Grid>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="Tag" Value="{x:Null}">
                <Setter TargetName="Icon" Property="Visibility" Value="Collapsed"/>
              </Trigger>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Overlay" Property="Opacity" Value="1"/>
              </Trigger>
              <Trigger Property="IsPressed" Value="True">
                <Setter TargetName="Overlay" Property="Background" Value="{DynamicResource PressedOverlay}"/>
                <Setter TargetName="Overlay" Property="Opacity" Value="1"/>
              </Trigger>
              <Trigger Property="IsKeyboardFocused" Value="True">
                <Setter TargetName="Bd" Property="BorderBrush" Value="{DynamicResource FocusBorder}"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter TargetName="Bd" Property="Opacity" Value="0.45"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="AccentButton" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Background" Value="{DynamicResource Accent}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource Accent}"/>
      <Setter Property="Foreground" Value="{DynamicResource AccentText}"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
    </Style>
    <Style x:Key="DangerButton" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Background" Value="{DynamicResource DangerBg}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource DangerBg}"/>
      <Setter Property="Foreground" Value="#FFFFFF"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
    </Style>
    <Style x:Key="SubtleButton" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="BorderBrush" Value="Transparent"/>
    </Style>
    <Style x:Key="HeaderButton" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Background" Value="#26FFFFFF"/>
      <Setter Property="BorderBrush" Value="#40FFFFFF"/>
      <Setter Property="Foreground" Value="#FFFFFF"/>
    </Style>
    <Style x:Key="LinkButton" TargetType="Button">
      <Setter Property="Foreground" Value="{DynamicResource Accent}"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="FocusVisualStyle" Value="{StaticResource KeyboardFocus}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <TextBlock x:Name="LinkText" Background="Transparent" VerticalAlignment="Center" Text="{Binding Content, RelativeSource={RelativeSource TemplatedParent}}"/>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="LinkText" Property="TextDecorations" Value="Underline"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- Inputs: Tag = "Warning" or "Invalid" colours the border -->
    <Style TargetType="TextBox">
      <Setter Property="Background" Value="{DynamicResource InputBg}"/>
      <Setter Property="Foreground" Value="{DynamicResource TextPrimary}"/>
      <Setter Property="CaretBrush" Value="{DynamicResource TextPrimary}"/>
      <Setter Property="SelectionBrush" Value="{DynamicResource Accent}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource InputBorder}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="8,6"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TextBox">
            <Border x:Name="Bd" CornerRadius="6" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" SnapsToDevicePixels="True">
              <ScrollViewer x:Name="PART_ContentHost" Focusable="False" HorizontalScrollBarVisibility="Hidden" VerticalScrollBarVisibility="Hidden"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="BorderBrush" Value="{DynamicResource InputHoverBorder}"/>
              </Trigger>
              <Trigger Property="IsKeyboardFocused" Value="True">
                <Setter TargetName="Bd" Property="BorderBrush" Value="{DynamicResource Accent}"/>
              </Trigger>
              <Trigger Property="Tag" Value="Warning">
                <Setter TargetName="Bd" Property="BorderBrush" Value="{DynamicResource WarningText}"/>
              </Trigger>
              <Trigger Property="Tag" Value="Invalid">
                <Setter TargetName="Bd" Property="BorderBrush" Value="{DynamicResource DangerText}"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter TargetName="Bd" Property="Opacity" Value="0.6"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="CheckBox">
      <Setter Property="Foreground" Value="{DynamicResource TextPrimary}"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="CheckBox">
            <StackPanel Orientation="Horizontal" Background="Transparent">
              <Border x:Name="Box" Width="16" Height="16" CornerRadius="3" BorderThickness="1" Background="{DynamicResource InputBg}" BorderBrush="{DynamicResource InputBorder}" VerticalAlignment="Center">
                <TextBlock x:Name="Mark" Text="&#xE73E;" FontFamily="Segoe Fluent Icons, Segoe MDL2 Assets" FontSize="11" Foreground="{DynamicResource AccentText}" HorizontalAlignment="Center" VerticalAlignment="Center" Visibility="Collapsed"/>
              </Border>
              <ContentPresenter Margin="8,0,0,0" VerticalAlignment="Center" RecognizesAccessKey="True"/>
            </StackPanel>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Box" Property="BorderBrush" Value="{DynamicResource InputHoverBorder}"/>
              </Trigger>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="Box" Property="Background" Value="{DynamicResource Accent}"/>
                <Setter TargetName="Box" Property="BorderBrush" Value="{DynamicResource Accent}"/>
                <Setter TargetName="Mark" Property="Visibility" Value="Visible"/>
              </Trigger>
              <Trigger Property="IsKeyboardFocused" Value="True">
                <Setter TargetName="Box" Property="BorderBrush" Value="{DynamicResource FocusBorder}"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter Property="Opacity" Value="0.5"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="ProgressBar">
      <Setter Property="Foreground" Value="{DynamicResource Accent}"/>
      <Setter Property="Background" Value="{DynamicResource InputBorder}"/>
      <Setter Property="BorderThickness" Value="0"/>
    </Style>

    <!-- Slim scrollbars that follow the theme (no arrow buttons) -->
    <Style x:Key="ScrollThumbV" TargetType="Thumb">
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Thumb">
            <Border Background="Transparent">
              <Border x:Name="ThumbBd" Margin="3,0" CornerRadius="3" Background="{DynamicResource InputBorder}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="ThumbBd" Property="Background" Value="{DynamicResource InputHoverBorder}"/>
              </Trigger>
              <Trigger Property="IsDragging" Value="True">
                <Setter TargetName="ThumbBd" Property="Background" Value="{DynamicResource InputHoverBorder}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="ScrollThumbH" TargetType="Thumb">
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Thumb">
            <Border Background="Transparent">
              <Border x:Name="ThumbBd" Margin="0,3" CornerRadius="3" Background="{DynamicResource InputBorder}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="ThumbBd" Property="Background" Value="{DynamicResource InputHoverBorder}"/>
              </Trigger>
              <Trigger Property="IsDragging" Value="True">
                <Setter TargetName="ThumbBd" Property="Background" Value="{DynamicResource InputHoverBorder}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="ScrollPage" TargetType="RepeatButton">
      <Setter Property="Focusable" Value="False"/>
      <Setter Property="IsTabStop" Value="False"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="RepeatButton">
            <Border Background="Transparent"/>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <ControlTemplate x:Key="VerticalScroll" TargetType="ScrollBar">
      <Border Background="{TemplateBinding Background}">
        <Track x:Name="PART_Track" IsDirectionReversed="True">
          <Track.DecreaseRepeatButton>
            <RepeatButton Style="{StaticResource ScrollPage}" Command="{x:Static ScrollBar.PageUpCommand}"/>
          </Track.DecreaseRepeatButton>
          <Track.IncreaseRepeatButton>
            <RepeatButton Style="{StaticResource ScrollPage}" Command="{x:Static ScrollBar.PageDownCommand}"/>
          </Track.IncreaseRepeatButton>
          <Track.Thumb>
            <Thumb Style="{StaticResource ScrollThumbV}"/>
          </Track.Thumb>
        </Track>
      </Border>
    </ControlTemplate>
    <ControlTemplate x:Key="HorizontalScroll" TargetType="ScrollBar">
      <Border Background="{TemplateBinding Background}">
        <Track x:Name="PART_Track" IsDirectionReversed="False">
          <Track.DecreaseRepeatButton>
            <RepeatButton Style="{StaticResource ScrollPage}" Command="{x:Static ScrollBar.PageLeftCommand}"/>
          </Track.DecreaseRepeatButton>
          <Track.IncreaseRepeatButton>
            <RepeatButton Style="{StaticResource ScrollPage}" Command="{x:Static ScrollBar.PageRightCommand}"/>
          </Track.IncreaseRepeatButton>
          <Track.Thumb>
            <Thumb Style="{StaticResource ScrollThumbH}"/>
          </Track.Thumb>
        </Track>
      </Border>
    </ControlTemplate>
    <Style TargetType="ScrollBar">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="Template" Value="{StaticResource VerticalScroll}"/>
      <Setter Property="Width" Value="12"/>
      <Setter Property="MinWidth" Value="12"/>
      <Style.Triggers>
        <Trigger Property="Orientation" Value="Horizontal">
          <Setter Property="Template" Value="{StaticResource HorizontalScroll}"/>
          <Setter Property="Width" Value="Auto"/>
          <Setter Property="MinWidth" Value="0"/>
          <Setter Property="Height" Value="12"/>
          <Setter Property="MinHeight" Value="12"/>
        </Trigger>
      </Style.Triggers>
    </Style>

    <!-- Left-hand navigation: Tag holds the icon glyph -->
    <Style x:Key="NavListStyle" TargetType="ListBox">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="ScrollViewer.HorizontalScrollBarVisibility" Value="Disabled"/>
    </Style>
    <Style x:Key="NavItem" TargetType="ListBoxItem">
      <Setter Property="Foreground" Value="{DynamicResource TextPrimary}"/>
      <Setter Property="Padding" Value="12,9"/>
      <Setter Property="Margin" Value="8,2"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="FocusVisualStyle" Value="{StaticResource KeyboardFocus}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ListBoxItem">
            <Border x:Name="Bd" CornerRadius="6" Background="Transparent">
              <Grid>
                <Border x:Name="Bar" Width="3" CornerRadius="2" HorizontalAlignment="Left" Margin="0,9" Background="{DynamicResource Accent}" Visibility="Hidden"/>
                <StackPanel Orientation="Horizontal" Margin="{TemplateBinding Padding}">
                  <TextBlock Text="{Binding Tag, RelativeSource={RelativeSource TemplatedParent}}" FontFamily="Segoe Fluent Icons, Segoe MDL2 Assets" FontSize="16" Width="22" VerticalAlignment="Center"/>
                  <ContentPresenter VerticalAlignment="Center" Margin="8,0,0,0"/>
                </StackPanel>
              </Grid>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="{DynamicResource NavHover}"/>
              </Trigger>
              <Trigger Property="IsSelected" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="{DynamicResource NavSelected}"/>
                <Setter TargetName="Bar" Property="Visibility" Value="Visible"/>
                <Setter Property="FontWeight" Value="SemiBold"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- Grids -->
    <Style TargetType="DataGrid">
      <Setter Property="Background" Value="{DynamicResource CardBg}"/>
      <Setter Property="Foreground" Value="{DynamicResource TextPrimary}"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="RowBackground" Value="{DynamicResource CardBg}"/>
      <Setter Property="AlternatingRowBackground" Value="{DynamicResource GridAlt}"/>
      <Setter Property="HorizontalGridLinesBrush" Value="{DynamicResource GridLine}"/>
      <Setter Property="GridLinesVisibility" Value="Horizontal"/>
      <Setter Property="HeadersVisibility" Value="Column"/>
      <Setter Property="RowHeaderWidth" Value="0"/>
      <Setter Property="MinRowHeight" Value="30"/>
      <Setter Property="CanUserResizeRows" Value="False"/>
    </Style>
    <Style TargetType="DataGridColumnHeader">
      <Setter Property="Background" Value="{DynamicResource GridHeaderBg}"/>
      <Setter Property="Foreground" Value="{DynamicResource TextSecondary}"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Padding" Value="10,7"/>
      <Setter Property="BorderBrush" Value="{DynamicResource GridLine}"/>
      <Setter Property="BorderThickness" Value="0,0,0,1"/>
      <Setter Property="HorizontalContentAlignment" Value="Left"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="DataGridColumnHeader">
            <Grid>
              <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" Padding="{TemplateBinding Padding}">
                <DockPanel>
                  <TextBlock x:Name="SortIcon" DockPanel.Dock="Right" FontFamily="Segoe Fluent Icons, Segoe MDL2 Assets" FontSize="10" Margin="6,0,0,0" VerticalAlignment="Center" Visibility="Collapsed"/>
                  <ContentPresenter HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}" VerticalAlignment="Center"/>
                </DockPanel>
              </Border>
              <Thumb x:Name="PART_LeftHeaderGripper" HorizontalAlignment="Left" Width="6" Cursor="SizeWE" Opacity="0"/>
              <Thumb x:Name="PART_RightHeaderGripper" HorizontalAlignment="Right" Width="6" Cursor="SizeWE" Opacity="0"/>
            </Grid>
            <ControlTemplate.Triggers>
              <Trigger Property="SortDirection" Value="Ascending">
                <Setter TargetName="SortIcon" Property="Text" Value="&#xE70E;"/>
                <Setter TargetName="SortIcon" Property="Visibility" Value="Visible"/>
              </Trigger>
              <Trigger Property="SortDirection" Value="Descending">
                <Setter TargetName="SortIcon" Property="Text" Value="&#xE70D;"/>
                <Setter TargetName="SortIcon" Property="Visibility" Value="Visible"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="DataGridCell">
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="FocusVisualStyle" Value="{StaticResource KeyboardFocus}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="DataGridCell">
            <Border Background="{TemplateBinding Background}" Padding="10,0" SnapsToDevicePixels="True">
              <ContentPresenter VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="IsSelected" Value="True">
          <Setter Property="Background" Value="{DynamicResource GridSelect}"/>
          <Setter Property="Foreground" Value="{DynamicResource TextPrimary}"/>
        </Trigger>
      </Style.Triggers>
    </Style>
    <!-- Failed rows in any results grid show in red -->
    <Style TargetType="DataGridRow">
      <Style.Triggers>
        <DataTrigger Binding="{Binding Result}" Value="Failed">
          <Setter Property="Foreground" Value="{DynamicResource DangerText}"/>
        </DataTrigger>
      </Style.Triggers>
    </Style>

    <!-- Coloured labels for the Result and Status columns -->
    <DataTemplate x:Key="ResultChipTemplate">
      <Border x:Name="Chip" CornerRadius="9" Padding="8,1" HorizontalAlignment="Left" VerticalAlignment="Center" Background="{DynamicResource ChipInfoBg}">
        <TextBlock x:Name="ChipText" Text="{Binding Result}" FontSize="12" FontWeight="SemiBold" Foreground="{DynamicResource ChipInfoFg}"/>
      </Border>
      <DataTemplate.Triggers>
        <DataTrigger Binding="{Binding Result}" Value="Success">
          <Setter TargetName="Chip" Property="Background" Value="{DynamicResource ChipSuccessBg}"/>
          <Setter TargetName="ChipText" Property="Foreground" Value="{DynamicResource ChipSuccessFg}"/>
        </DataTrigger>
        <DataTrigger Binding="{Binding Result}" Value="Failed">
          <Setter TargetName="Chip" Property="Background" Value="{DynamicResource ChipFailedBg}"/>
          <Setter TargetName="ChipText" Property="Foreground" Value="{DynamicResource ChipFailedFg}"/>
        </DataTrigger>
        <DataTrigger Binding="{Binding Result}" Value="Skipped">
          <Setter TargetName="Chip" Property="Background" Value="{DynamicResource ChipSkippedBg}"/>
          <Setter TargetName="ChipText" Property="Foreground" Value="{DynamicResource ChipSkippedFg}"/>
        </DataTrigger>
      </DataTemplate.Triggers>
    </DataTemplate>
    <DataTemplate x:Key="StatusChipTemplate">
      <Border x:Name="Chip" CornerRadius="9" Padding="8,1" HorizontalAlignment="Left" VerticalAlignment="Center" Background="{DynamicResource ChipInfoBg}">
        <TextBlock x:Name="ChipText" Text="{Binding Status}" FontSize="12" FontWeight="SemiBold" Foreground="{DynamicResource ChipInfoFg}"/>
      </Border>
      <DataTemplate.Triggers>
        <DataTrigger Binding="{Binding Status}" Value="Active">
          <Setter TargetName="Chip" Property="Background" Value="{DynamicResource ChipSuccessBg}"/>
          <Setter TargetName="ChipText" Property="Foreground" Value="{DynamicResource ChipSuccessFg}"/>
        </DataTrigger>
      </DataTemplate.Triggers>
    </DataTemplate>
'@

# Use single-quoted here-strings to prevent PS variable interpolation inside XAML
$mainXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Purview Case Tools" Height="800" Width="1120" MinHeight="640" MinWidth="900"
        WindowStartupLocation="CenterScreen" FontFamily="Segoe UI" FontSize="13"
        TextOptions.TextFormattingMode="Display"
        Background="{DynamicResource WindowBg}" Foreground="{DynamicResource TextPrimary}">
  <Window.Resources>
<!--THEME-->
  </Window.Resources>
  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <!-- Header: banner, connection and Connect button -->
    <Border Grid.Row="0" Background="#185951">
      <DockPanel Height="64" LastChildFill="False">
        <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center" Margin="0,0,16,0">
          <Border CornerRadius="12" Background="#33000000" Padding="10,5" Margin="0,0,12,0" VerticalAlignment="Center">
            <StackPanel Orientation="Horizontal">
              <Ellipse x:Name="ConnDot" Width="8" Height="8" Margin="0,0,8,0" VerticalAlignment="Center" Fill="#9CA3AF"/>
              <TextBlock x:Name="TxtConn" Text="Not connected" Foreground="#FFFFFF" VerticalAlignment="Center" MaxWidth="320" TextTrimming="CharacterEllipsis"/>
            </StackPanel>
          </Border>
          <Button x:Name="BtnConnect" Style="{StaticResource HeaderButton}" Tag="&#xE703;" Content="Connect" ToolTip="Sign in to Security &amp; Compliance and load the case list"/>
        </StackPanel>
        <Image x:Name="HeaderBanner" DockPanel.Dock="Left" Height="64" Stretch="Uniform" HorizontalAlignment="Left" RenderOptions.BitmapScalingMode="HighQuality" SnapsToDevicePixels="True"/>
      </DockPanel>
    </Border>

    <Grid Grid.Row="1">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="232"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>

      <!-- Navigation -->
      <Border Grid.Column="0" Background="{DynamicResource NavBg}" BorderBrush="{DynamicResource CardBorder}" BorderThickness="0,0,1,0">
        <DockPanel>
          <StackPanel DockPanel.Dock="Bottom" Margin="8,8,8,12">
            <Button x:Name="ThemeToggle" Style="{StaticResource SubtleButton}" Tag="&#xE790;" Content="Theme: System" HorizontalContentAlignment="Left" ToolTip="Switch between System, Light and Dark"/>
          </StackPanel>
          <ListBox x:Name="NavList" Style="{StaticResource NavListStyle}" Margin="0,12,0,0">
            <ListBoxItem Style="{StaticResource NavItem}" Tag="&#xE8F1;" Content="Cases" ToolTip="Ctrl+1"/>
            <ListBoxItem Style="{StaticResource NavItem}" Tag="&#xE8FA;" Content="Add Reviewers" ToolTip="Ctrl+2"/>
            <ListBoxItem Style="{StaticResource NavItem}" Tag="&#xE8F8;" Content="Remove Reviewers" ToolTip="Ctrl+3"/>
            <ListBoxItem Style="{StaticResource NavItem}" Tag="&#xE896;" Content="Export Case Permissions" ToolTip="Ctrl+4"/>
            <ListBoxItem Style="{StaticResource NavItem}" Tag="&#xE72E;" Content="Close Cases" ToolTip="Ctrl+5"/>
            <ListBoxItem Style="{StaticResource NavItem}" Tag="&#xE74D;" Content="Delete Cases" ToolTip="Ctrl+6"/>
          </ListBox>
        </DockPanel>
      </Border>

      <!-- Pages: one is visible at a time, chosen by the navigation list -->
      <Grid Grid.Column="1" Margin="24,20,24,8">

        <!-- Cases: list, search, reopen -->
        <Grid x:Name="Page_Cases">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="2*"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <StackPanel Margin="0,0,0,16">
            <TextBlock Text="Cases" Style="{StaticResource PageTitle}"/>
            <TextBlock Text="Browse the eDiscovery cases in your tenant, reopen closed ones, or copy names to use on another page." Style="{StaticResource PageSubtitle}"/>
          </StackPanel>
          <Border Grid.Row="1" Style="{StaticResource Card}" Padding="0">
            <Grid>
              <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
                <RowDefinition Height="Auto"/>
              </Grid.RowDefinitions>
              <DockPanel Margin="16,12">
                <Button x:Name="BtnCases_Refresh" DockPanel.Dock="Right" Tag="&#xE72C;" Content="Refresh" Margin="12,0,0,0" ToolTip="F5"/>
                <CheckBox x:Name="ChkCases_Closed" DockPanel.Dock="Right" Content="Show closed cases" IsChecked="True" VerticalAlignment="Center" Margin="12,0,0,0"/>
                <TextBlock DockPanel.Dock="Left" Text="&#xE721;" FontFamily="Segoe Fluent Icons, Segoe MDL2 Assets" Foreground="{DynamicResource TextSecondary}" VerticalAlignment="Center" Margin="0,0,8,0"/>
                <TextBox x:Name="TxtCases_Search" VerticalContentAlignment="Center" ToolTip="Search by case name / ECM reference"/>
              </DockPanel>
              <DataGrid Grid.Row="1" x:Name="GridCases" Margin="1,0,1,0"/>
              <TextBlock Grid.Row="2" x:Name="TxtCases_Count" Style="{StaticResource Hint}" Margin="16,8,16,10" Text="Connect to load the case list."/>
            </Grid>
          </Border>
          <StackPanel Grid.Row="2" Orientation="Horizontal" Margin="0,0,0,16">
            <Button x:Name="BtnCases_Reopen" Style="{StaticResource AccentButton}" Tag="&#xE785;" Content="Reopen Selected" Margin="0,0,10,0"/>
            <Button x:Name="BtnCases_Copy" Tag="&#xE8C8;" Content="Copy Selected Names"/>
          </StackPanel>
          <Border Grid.Row="3" Style="{StaticResource Card}" Padding="0" Margin="0">
            <Grid>
              <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
              </Grid.RowDefinitions>
              <DockPanel Margin="16,10">
                <Button x:Name="BtnCases_Save" DockPanel.Dock="Right" Style="{StaticResource SubtleButton}" Tag="&#xE74E;" Content="Save as CSV"/>
                <TextBlock Text="Results" Style="{StaticResource SectionTitle}"/>
                <TextBlock x:Name="SumCases" Style="{StaticResource Hint}" Margin="12,0,0,0" VerticalAlignment="Center"/>
              </DockPanel>
              <DataGrid Grid.Row="1" x:Name="GridCases_Results" Margin="1,0,1,1"/>
            </Grid>
          </Border>
        </Grid>

        <!-- Add Reviewers -->
        <Grid x:Name="Page_Add" Visibility="Collapsed">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <StackPanel Margin="0,0,0,16">
            <TextBlock Text="Add Reviewers" Style="{StaticResource PageTitle}"/>
            <TextBlock Text="Add one or more reviewers to one or more cases." Style="{StaticResource PageSubtitle}"/>
          </StackPanel>
          <Border Grid.Row="1" Style="{StaticResource Card}">
            <Grid>
              <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="20"/>
                <ColumnDefinition Width="*"/>
              </Grid.ColumnDefinitions>
              <StackPanel>
                <DockPanel Margin="0,0,0,6">
                  <Button x:Name="BtnAdd_Pick" DockPanel.Dock="Right" Style="{StaticResource SubtleButton}" Tag="&#xE710;" Content="Pick Cases..." Padding="8,3"/>
                  <TextBlock Text="Case Name / ECM Reference (one per line)" Style="{StaticResource FieldLabel}" Margin="0" VerticalAlignment="Center"/>
                </DockPanel>
                <TextBox x:Name="TxtAdd_Cases" Height="96" AcceptsReturn="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"/>
                <TextBlock x:Name="HintAdd_Cases" Style="{StaticResource Hint}"/>
              </StackPanel>
              <StackPanel Grid.Column="2">
                <TextBlock Text="Reviewers to add (one per line)" Style="{StaticResource FieldLabel}" Margin="0,4,0,8"/>
                <TextBox x:Name="TxtAdd_Emails" Height="96" AcceptsReturn="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"/>
                <TextBlock x:Name="HintAdd_Emails" Style="{StaticResource Hint}"/>
              </StackPanel>
            </Grid>
          </Border>
          <StackPanel Grid.Row="2" Orientation="Horizontal" Margin="0,0,0,16">
            <Button x:Name="BtnAdd_Run" Style="{StaticResource AccentButton}" Tag="&#xE8FA;" Content="Add Reviewers" ToolTip="Ctrl+Enter"/>
          </StackPanel>
          <Border Grid.Row="3" Style="{StaticResource Card}" Padding="0" Margin="0">
            <Grid>
              <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
              </Grid.RowDefinitions>
              <DockPanel Margin="16,10">
                <Button x:Name="BtnAdd_Save" DockPanel.Dock="Right" Style="{StaticResource SubtleButton}" Tag="&#xE74E;" Content="Save as CSV"/>
                <TextBlock Text="Results" Style="{StaticResource SectionTitle}"/>
                <TextBlock x:Name="SumAdd" Style="{StaticResource Hint}" Margin="12,0,0,0" VerticalAlignment="Center"/>
              </DockPanel>
              <DataGrid Grid.Row="1" x:Name="GridAdd_Results" Margin="1,0,1,1"/>
            </Grid>
          </Border>
        </Grid>

        <!-- Remove Reviewers (bulk + replacement) -->
        <Grid x:Name="Page_Rem" Visibility="Collapsed">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <StackPanel Margin="0,0,0,16">
            <TextBlock Text="Remove Reviewers" Style="{StaticResource PageTitle}"/>
            <TextBlock Text="Remove reviewers from cases. The replacement is added first, as every case needs at least one member." Style="{StaticResource PageSubtitle}"/>
          </StackPanel>
          <Border Grid.Row="1" Style="{StaticResource Card}">
            <Grid>
              <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="20"/>
                <ColumnDefinition Width="*"/>
              </Grid.ColumnDefinitions>
              <StackPanel>
                <DockPanel Margin="0,0,0,6">
                  <Button x:Name="BtnRem_Pick" DockPanel.Dock="Right" Style="{StaticResource SubtleButton}" Tag="&#xE710;" Content="Pick Cases..." Padding="8,3"/>
                  <TextBlock Text="Case Name / ECM Reference (one per line)" Style="{StaticResource FieldLabel}" Margin="0" VerticalAlignment="Center"/>
                </DockPanel>
                <TextBox x:Name="TxtRem_Cases" Height="80" AcceptsReturn="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"/>
                <TextBlock x:Name="HintRem_Cases" Style="{StaticResource Hint}"/>
              </StackPanel>
              <StackPanel Grid.Column="2">
                <TextBlock Text="Reviewers to remove (one per line)" Style="{StaticResource FieldLabel}" Margin="0,4,0,8"/>
                <TextBox x:Name="TxtRem_Emails" Height="80" AcceptsReturn="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"/>
                <TextBlock x:Name="HintRem_Emails" Style="{StaticResource Hint}" Text="Leave empty to remove everyone except the replacement."/>
              </StackPanel>
            </Grid>
          </Border>
          <StackPanel Grid.Row="2" Margin="0,0,0,16">
            <StackPanel Orientation="Horizontal">
              <TextBlock Text="Replacement reviewer" Style="{StaticResource FieldLabel}" Margin="0,0,10,0" VerticalAlignment="Center"/>
              <TextBox x:Name="TxtRem_Replacement" Width="280" VerticalAlignment="Center" ToolTip="Cases must have at least 1 member, so this person is added before anyone is removed."/>
              <Button x:Name="BtnRem_Run" Style="{StaticResource AccentButton}" Tag="&#xE8F8;" Content="Remove + Replace" ToolTip="Ctrl+Enter" Margin="12,0,0,0"/>
            </StackPanel>
            <TextBlock x:Name="HintRem_Replacement" Style="{StaticResource Hint}" Visibility="Collapsed"/>
          </StackPanel>
          <Border Grid.Row="3" Style="{StaticResource Card}" Padding="0" Margin="0">
            <Grid>
              <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
              </Grid.RowDefinitions>
              <DockPanel Margin="16,10">
                <Button x:Name="BtnRem_Save" DockPanel.Dock="Right" Style="{StaticResource SubtleButton}" Tag="&#xE74E;" Content="Save as CSV"/>
                <TextBlock Text="Results" Style="{StaticResource SectionTitle}"/>
                <TextBlock x:Name="SumRem" Style="{StaticResource Hint}" Margin="12,0,0,0" VerticalAlignment="Center"/>
              </DockPanel>
              <DataGrid Grid.Row="1" x:Name="GridRem_Results" Margin="1,0,1,1"/>
            </Grid>
          </Border>
        </Grid>

        <!-- Export Case Permissions -->
        <Grid x:Name="Page_Export" Visibility="Collapsed">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <StackPanel Margin="0,0,0,16">
            <TextBlock Text="Export Case Permissions" Style="{StaticResource PageTitle}"/>
            <TextBlock x:Name="TxtExport_Info" Text="Writes one CSV of members per case to the logs folder." Style="{StaticResource PageSubtitle}"/>
          </StackPanel>
          <Border Grid.Row="1" Style="{StaticResource Card}">
            <StackPanel>
              <DockPanel Margin="0,0,0,6">
                <Button x:Name="BtnExport_Pick" DockPanel.Dock="Right" Style="{StaticResource SubtleButton}" Tag="&#xE710;" Content="Pick Cases..." Padding="8,3"/>
                <TextBlock Text="Case Name / ECM Reference (one per line)" Style="{StaticResource FieldLabel}" Margin="0" VerticalAlignment="Center"/>
              </DockPanel>
              <TextBox x:Name="TxtExport_Cases" Height="110" AcceptsReturn="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"/>
              <TextBlock x:Name="HintExport_Cases" Style="{StaticResource Hint}"/>
            </StackPanel>
          </Border>
          <StackPanel Grid.Row="2" Orientation="Horizontal" Margin="0,0,0,16">
            <Button x:Name="BtnExport_Run" Style="{StaticResource AccentButton}" Tag="&#xE896;" Content="Export Case Permissions" ToolTip="Ctrl+Enter"/>
          </StackPanel>
          <Border Grid.Row="3" Style="{StaticResource Card}" Padding="0" Margin="0">
            <Grid>
              <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
              </Grid.RowDefinitions>
              <DockPanel Margin="16,10">
                <Button x:Name="BtnExport_Save" DockPanel.Dock="Right" Style="{StaticResource SubtleButton}" Tag="&#xE74E;" Content="Save as CSV"/>
                <TextBlock Text="Results" Style="{StaticResource SectionTitle}"/>
                <TextBlock x:Name="SumExport" Style="{StaticResource Hint}" Margin="12,0,0,0" VerticalAlignment="Center"/>
              </DockPanel>
              <DataGrid Grid.Row="1" x:Name="GridExport_Results" Margin="1,0,1,1"/>
            </Grid>
          </Border>
        </Grid>

        <!-- Close Cases -->
        <Grid x:Name="Page_Close" Visibility="Collapsed">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <StackPanel Margin="0,0,0,16">
            <TextBlock Text="Close Cases" Style="{StaticResource PageTitle}"/>
            <TextBlock Text="Close one or more cases. Closed cases can be reopened from the Cases page." Style="{StaticResource PageSubtitle}"/>
          </StackPanel>
          <Border Grid.Row="1" Style="{StaticResource Card}">
            <StackPanel>
              <DockPanel Margin="0,0,0,6">
                <Button x:Name="BtnClose_Pick" DockPanel.Dock="Right" Style="{StaticResource SubtleButton}" Tag="&#xE710;" Content="Pick Cases..." Padding="8,3"/>
                <TextBlock Text="Case Name / ECM Reference to close (one per line)" Style="{StaticResource FieldLabel}" Margin="0" VerticalAlignment="Center"/>
              </DockPanel>
              <TextBox x:Name="TxtClose_Cases" Height="110" AcceptsReturn="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"/>
              <TextBlock x:Name="HintClose_Cases" Style="{StaticResource Hint}"/>
            </StackPanel>
          </Border>
          <StackPanel Grid.Row="2" Orientation="Horizontal" Margin="0,0,0,16">
            <Button x:Name="BtnClose_Run" Style="{StaticResource AccentButton}" Tag="&#xE72E;" Content="Close Cases" ToolTip="Ctrl+Enter"/>
          </StackPanel>
          <Border Grid.Row="3" Style="{StaticResource Card}" Padding="0" Margin="0">
            <Grid>
              <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
              </Grid.RowDefinitions>
              <DockPanel Margin="16,10">
                <Button x:Name="BtnClose_Save" DockPanel.Dock="Right" Style="{StaticResource SubtleButton}" Tag="&#xE74E;" Content="Save as CSV"/>
                <TextBlock Text="Results" Style="{StaticResource SectionTitle}"/>
                <TextBlock x:Name="SumClose" Style="{StaticResource Hint}" Margin="12,0,0,0" VerticalAlignment="Center"/>
              </DockPanel>
              <DataGrid Grid.Row="1" x:Name="GridClose_Results" Margin="1,0,1,1"/>
            </Grid>
          </Border>
        </Grid>

        <!-- Delete Cases -->
        <Grid x:Name="Page_Delete" Visibility="Collapsed">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <StackPanel Margin="0,0,0,16">
            <TextBlock Text="Delete Cases" Style="{StaticResource PageTitle}"/>
            <TextBlock Text="Permanently delete one or more cases. This cannot be undone." Style="{StaticResource PageSubtitle}"/>
          </StackPanel>
          <Border Grid.Row="1" Style="{StaticResource Card}">
            <StackPanel>
              <DockPanel Margin="0,0,0,6">
                <Button x:Name="BtnDelete_Pick" DockPanel.Dock="Right" Style="{StaticResource SubtleButton}" Tag="&#xE710;" Content="Pick Cases..." Padding="8,3"/>
                <TextBlock Text="Case Name / ECM Reference to delete (one per line)" Style="{StaticResource FieldLabel}" Margin="0" VerticalAlignment="Center"/>
              </DockPanel>
              <TextBox x:Name="TxtDelete_Cases" Height="110" AcceptsReturn="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"/>
              <TextBlock x:Name="HintDelete_Cases" Style="{StaticResource Hint}"/>
            </StackPanel>
          </Border>
          <StackPanel Grid.Row="2" Orientation="Horizontal" Margin="0,0,0,16">
            <Button x:Name="BtnDelete_Run" Style="{StaticResource DangerButton}" Tag="&#xE74D;" Content="Delete Cases" ToolTip="Ctrl+Enter"/>
          </StackPanel>
          <Border Grid.Row="3" Style="{StaticResource Card}" Padding="0" Margin="0">
            <Grid>
              <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
              </Grid.RowDefinitions>
              <DockPanel Margin="16,10">
                <Button x:Name="BtnDelete_Save" DockPanel.Dock="Right" Style="{StaticResource SubtleButton}" Tag="&#xE74E;" Content="Save as CSV"/>
                <TextBlock Text="Results" Style="{StaticResource SectionTitle}"/>
                <TextBlock x:Name="SumDelete" Style="{StaticResource Hint}" Margin="12,0,0,0" VerticalAlignment="Center"/>
              </DockPanel>
              <DataGrid Grid.Row="1" x:Name="GridDelete_Results" Margin="1,0,1,1"/>
            </Grid>
          </Border>
        </Grid>
      </Grid>
    </Grid>

    <!-- Status bar: progress, last result, shortcuts, logs -->
    <Border Grid.Row="2" Background="{DynamicResource StatusBg}" BorderBrush="{DynamicResource CardBorder}" BorderThickness="0,1,0,0" Padding="16,7">
      <DockPanel>
        <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" Margin="16,0,0,0">
          <TextBlock x:Name="TxtShortcuts" Text="Ctrl+Enter runs this page  |  F5 refreshes cases  |  Ctrl+1 to 6 switch pages" Foreground="{DynamicResource TextSecondary}" FontSize="12" VerticalAlignment="Center" Margin="0,0,16,0"/>
          <Button x:Name="LinkLogs" Style="{StaticResource LinkButton}" Content="Open logs folder"/>
        </StackPanel>
        <ProgressBar x:Name="BusyProgress" DockPanel.Dock="Left" Width="160" Height="6" Margin="0,0,10,0" VerticalAlignment="Center" Visibility="Collapsed"/>
        <TextBlock x:Name="TxtWorking" DockPanel.Dock="Left" VerticalAlignment="Center" Foreground="{DynamicResource TextSecondary}" Margin="0,0,12,0"/>
        <TextBlock x:Name="TxtStatus" VerticalAlignment="Center" FontWeight="SemiBold" TextTrimming="CharacterEllipsis"/>
      </DockPanel>
    </Border>
  </Grid>
</Window>
'@

# Case picker dialog, opened from the "Pick Cases..." buttons
$pickerXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Pick Cases" Height="580" Width="760" MinHeight="320" MinWidth="480"
        WindowStartupLocation="CenterOwner" ShowInTaskbar="False" FontFamily="Segoe UI" FontSize="13"
        TextOptions.TextFormattingMode="Display"
        Background="{DynamicResource WindowBg}" Foreground="{DynamicResource TextPrimary}">
  <Window.Resources>
<!--THEME-->
  </Window.Resources>
  <Grid Margin="16">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>
    <DockPanel Margin="0,0,0,12">
      <CheckBox x:Name="ChkPick_Closed" DockPanel.Dock="Right" Content="Show closed cases" VerticalAlignment="Center" Margin="12,0,0,0"/>
      <TextBlock DockPanel.Dock="Left" Text="&#xE721;" FontFamily="Segoe Fluent Icons, Segoe MDL2 Assets" Foreground="{DynamicResource TextSecondary}" VerticalAlignment="Center" Margin="0,0,8,0"/>
      <TextBox x:Name="TxtPick_Search" VerticalContentAlignment="Center" ToolTip="Search by case name / ECM reference"/>
    </DockPanel>
    <Border Grid.Row="1" Style="{StaticResource Card}" Padding="1" Margin="0">
      <DataGrid x:Name="GridPick"/>
    </Border>
    <DockPanel Grid.Row="2" Margin="0,12,0,0">
      <Button x:Name="BtnPick_Cancel" DockPanel.Dock="Right" Content="Cancel" IsCancel="True" Margin="8,0,0,0"/>
      <Button x:Name="BtnPick_Ok" DockPanel.Dock="Right" Style="{StaticResource AccentButton}" Tag="&#xE73E;" Content="Add Selected" IsDefault="True"/>
      <TextBlock x:Name="TxtPick_Count" Style="{StaticResource Hint}" Margin="0,0,12,0" VerticalAlignment="Center"/>
    </DockPanel>
  </Grid>
</Window>
'@

Function New-ThemedWindow {
    param([string]$Xaml)
    [xml]$doc = $Xaml.Replace('<!--THEME-->', $ThemeXaml)
    [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $doc))
}

[xml]$xaml = $mainXaml.Replace('<!--THEME-->', $ThemeXaml)
$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

# Find every named control and expose it as a script variable of the same name
$xamlNs = 'http://schemas.microsoft.com/winfx/2006/xaml'
$nsMgr = New-Object System.Xml.XmlNamespaceManager($xaml.NameTable)
$nsMgr.AddNamespace('x', $xamlNs)
$controlNames = foreach ($node in $xaml.SelectNodes('//*[@x:Name]', $nsMgr)) { $node.GetAttribute('Name', $xamlNs) }
foreach ($name in $controlNames) {
    $control = $window.FindName($name)
    if ($control) { Set-Variable -Name $name -Value $control -Scope Script }
}
$AllButtons = foreach ($name in $controlNames -like 'Btn*') { Get-Variable -Name $name -ValueOnly }

# ------------------ Theme ------------------
$Palettes = @{
    Light = @{
        WindowBg = '#F4F6F8'; NavBg = '#EEF1F4'; StatusBg = '#EEF1F4'
        CardBg = '#FFFFFF'; CardBorder = '#E1E5EA'
        TextPrimary = '#1B1F24'; TextSecondary = '#5A6472'
        Accent = '#0F766E'; AccentText = '#FFFFFF'
        DangerBg = '#C42B1C'; DangerText = '#B42318'; WarningText = '#9A6700'; SuccessText = '#067647'
        InputBg = '#FFFFFF'; InputBorder = '#C8CFD8'; InputHoverBorder = '#98A2B3'
        ButtonBg = '#FFFFFF'; ButtonBorder = '#D0D5DD'
        HoverOverlay = '#0F000000'; PressedOverlay = '#1F000000'; FocusBorder = '#1B1F24'
        GridHeaderBg = '#F7F8FA'; GridLine = '#EAECF0'; GridAlt = '#FAFBFC'; GridSelect = '#D5F2EE'
        NavHover = '#E3E7EC'; NavSelected = '#FFFFFF'
        ChipSuccessBg = '#DCFAE6'; ChipSuccessFg = '#067647'
        ChipFailedBg  = '#FEE4E2'; ChipFailedFg  = '#B42318'
        ChipSkippedBg = '#FEF0C7'; ChipSkippedFg = '#93370D'
        ChipInfoBg    = '#EAECF0'; ChipInfoFg    = '#475467'
    }
    Dark = @{
        WindowBg = '#17191C'; NavBg = '#1F2226'; StatusBg = '#1F2226'
        CardBg = '#23272B'; CardBorder = '#343A40'
        TextPrimary = '#E8EAED'; TextSecondary = '#9AA4AF'
        Accent = '#2DD4BF'; AccentText = '#042F2E'
        DangerBg = '#B42318'; DangerText = '#FDA29B'; WarningText = '#FEC84B'; SuccessText = '#75E0A7'
        InputBg = '#1B1E22'; InputBorder = '#3F4650'; InputHoverBorder = '#5B6572'
        ButtonBg = '#2B3036'; ButtonBorder = '#3F4650'
        HoverOverlay = '#14FFFFFF'; PressedOverlay = '#24FFFFFF'; FocusBorder = '#E8EAED'
        GridHeaderBg = '#1F2327'; GridLine = '#30363D'; GridAlt = '#262A2F'; GridSelect = '#134E4A'
        NavHover = '#2A2F35'; NavSelected = '#2F353C'
        ChipSuccessBg = '#053321'; ChipSuccessFg = '#75E0A7'
        ChipFailedBg  = '#55160C'; ChipFailedFg  = '#FDA29B'
        ChipSkippedBg = '#4E1D09'; ChipSkippedFg = '#FEC84B'
        ChipInfoBg    = '#30363D'; ChipInfoFg    = '#CDD5DF'
    }
}
$script:ThemeMode = 'System'   # System, Light or Dark

# Light or Dark, from the Windows "app mode" setting
Function Get-WindowsAppTheme {
    try {
        $value = Get-ItemPropertyValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'AppsUseLightTheme' -ErrorAction Stop
        if ($value -eq 0) { return 'Dark' }
    } catch { }
    'Light'
}

Function Set-Theme {
    param([System.Windows.Window]$Target)
    $name = if ($script:ThemeMode -eq 'System') { Get-WindowsAppTheme } else { $script:ThemeMode }
    $palette = $Palettes[$name]
    foreach ($key in $palette.Keys) {
        $brush = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString($palette[$key]))
        $brush.Freeze()
        $Target.Resources[$key] = $brush
    }
    # The slim scroll bars have no arrow buttons; WPF sizes the smallest thumb at half this value
    $Target.Resources[[System.Windows.SystemParameters]::VerticalScrollBarButtonHeightKey] = [double]40
    $Target.Resources[[System.Windows.SystemParameters]::HorizontalScrollBarButtonWidthKey] = [double]40
    if ($Target -eq $window) {
        $ThemeToggle.Content = if ($script:ThemeMode -eq 'System') { 'Theme: System ({0})' -f $name } else { 'Theme: {0}' -f $name }
    }
}

# ------------------ Settings (window size, last page, theme) ------------------
Function Read-Settings {
    try {
        if (Test-Path -LiteralPath $SettingsPath) { return (Get-Content -LiteralPath $SettingsPath -Raw | ConvertFrom-Json) }
    } catch { Write-Log ("Could not read settings: {0}" -f $_.Exception.Message) 'WARN' }
    $null
}

Function Save-Settings {
    try {
        $dir = Split-Path -Parent $SettingsPath
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
        $bounds = if ($window.WindowState -eq 'Normal') { New-Object System.Windows.Rect($window.Left, $window.Top, $window.ActualWidth, $window.ActualHeight) } else { $window.RestoreBounds }
        $settings = [ordered]@{ Theme = $script:ThemeMode; Page = $NavList.SelectedIndex; Maximized = ($window.WindowState -eq 'Maximized') }
        if (-not $bounds.IsEmpty) {
            $settings.Left = $bounds.Left; $settings.Top = $bounds.Top
            $settings.Width = $bounds.Width; $settings.Height = $bounds.Height
        }
        [pscustomobject]$settings | ConvertTo-Json | Set-Content -LiteralPath $SettingsPath -Encoding UTF8
    } catch { Write-Log ("Could not save settings: {0}" -f $_.Exception.Message) 'WARN' }
}

Function Test-Number($value) {
    $n = 0.0
    [double]::TryParse([string]$value, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n) -and -not [double]::IsNaN($n) -and -not [double]::IsInfinity($n)
}

# Restores the saved window position only if it is still on one of the screens
Function Restore-Settings {
    param($Settings)
    if (-not $Settings) { return 0 }
    if ($Settings.Theme -in 'System', 'Light', 'Dark') { $script:ThemeMode = [string]$Settings.Theme }
    $screen = New-Object System.Windows.Rect([System.Windows.SystemParameters]::VirtualScreenLeft, [System.Windows.SystemParameters]::VirtualScreenTop, [System.Windows.SystemParameters]::VirtualScreenWidth, [System.Windows.SystemParameters]::VirtualScreenHeight)
    $haveSize = (Test-Number $Settings.Width) -and (Test-Number $Settings.Height)
    $width  = if ($haveSize) { [Math]::Max($window.MinWidth,  [Math]::Min([double]$Settings.Width,  $screen.Width)) }  else { $window.Width }
    $height = if ($haveSize) { [Math]::Max($window.MinHeight, [Math]::Min([double]$Settings.Height, $screen.Height)) } else { $window.Height }
    $restored = $false
    if ((Test-Number $Settings.Left) -and (Test-Number $Settings.Top)) {
        $left = [double]$Settings.Left; $top = [double]$Settings.Top
        $topLeft     = New-Object System.Windows.Point(($left + 20), ($top + 10))
        $bottomRight = New-Object System.Windows.Point(($left + $width - 20), ($top + $height - 10))
        if ($screen.Contains($topLeft) -and $screen.Contains($bottomRight)) {
            $window.WindowStartupLocation = 'Manual'
            $window.Left = $left; $window.Top = $top
            $window.Width = $width; $window.Height = $height
            $restored = $true
        }
    }
    # Otherwise the window opens centred on the main screen, so fit it to that screen
    if ($haveSize -and -not $restored) {
        $workArea = [System.Windows.SystemParameters]::WorkArea
        $window.Width  = [Math]::Max($window.MinWidth,  [Math]::Min([double]$Settings.Width,  $workArea.Width))
        $window.Height = [Math]::Max($window.MinHeight, [Math]::Min([double]$Settings.Height, $workArea.Height))
    }
    if ($Settings.Maximized -eq $true) { $window.WindowState = 'Maximized' }
    $page = 0
    if ((Test-Number $Settings.Page) -and [int]$Settings.Page -ge 0 -and [int]$Settings.Page -le 5) { $page = [int]$Settings.Page }
    $page
}

# ------------------ UI Helpers (progress / status / busy) ------------------
Function Set-Status {
    param([string]$Message, [ValidateSet('Success','Error','Neutral')][string]$Kind = 'Success')
    $TxtStatus.Text = $Message
    $TxtStatus.ToolTip = if ($Message) { $Message } else { $null }
    $key = switch ($Kind) { 'Error' { 'DangerText' } 'Neutral' { 'TextSecondary' } default { 'SuccessText' } }
    $TxtStatus.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, $key)
}
Function Show-Busy {
    $BusyProgress.IsIndeterminate = $true
    $BusyProgress.Visibility = 'Visible'
    $TxtWorking.Text = 'Working...'
}
Function Hide-Busy {
    $BusyProgress.Visibility = 'Collapsed'
    $BusyProgress.IsIndeterminate = $false
    $TxtWorking.Text = ''
}
Function Update-BusyProgress {
    $p = $Shared.Progress
    if ($p -and $p.Total -gt 0) {
        $BusyProgress.IsIndeterminate = $false
        $BusyProgress.Maximum = $p.Total
        $BusyProgress.Value = [Math]::Min($p.Done, $p.Total)
        $TxtWorking.Text = '{0} of {1} {2} done' -f $p.Done, $p.Total, $p.Unit
    }
}
Function Set-UIBusy([bool]$busy) {
    foreach ($c in $AllButtons) { if ($c) { $c.IsEnabled = -not $busy } }
}
$ConnOnBrush  = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString('#4ADE80'))
$ConnOffBrush = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString('#9CA3AF'))
Function Update-ConnectionText {
    if ($Shared.IsConnected) {
        $TxtConn.Text = if ($Shared.Account) { $Shared.Account } else { 'Connected' }
        $TxtConn.ToolTip = if ($Shared.Tenant) { 'Connected to Security & Compliance as {0}, tenant {1}' -f $Shared.Account, $Shared.Tenant } else { $null }
        $ConnDot.Fill = $ConnOnBrush
        $BtnConnect.Content = 'Refresh'
        $BtnConnect.Tag = [string][char]0xE72C
        $BtnConnect.ToolTip = 'Check the session and reload the case list'
    } else {
        $TxtConn.Text = 'Not connected'
        $TxtConn.ToolTip = $null
        $ConnDot.Fill = $ConnOffBrush
        $BtnConnect.Content = 'Connect'
        $BtnConnect.Tag = [string][char]0xE703
        $BtnConnect.ToolTip = 'Sign in to Security & Compliance and load the case list'
    }
}
Function Invoke-ButtonClick([System.Windows.Controls.Button]$Button) {
    if ($Button -and $Button.IsEnabled) {
        $Button.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
    }
}

$LinkLogs.ToolTip = $logFile
# The shortcut reminder gives way to the status text on narrow windows
$window.Add_SizeChanged({ $TxtShortcuts.Visibility = if ($window.ActualWidth -lt 1080) { 'Collapsed' } else { 'Visible' } })
$TxtExport_Info.Text = "Writes one CSV of members per case to $logDir."

# ------------------ Navigation ------------------
$Pages = @($Page_Cases, $Page_Add, $Page_Rem, $Page_Export, $Page_Close, $Page_Delete)
$PageRunButtons = @($BtnCases_Refresh, $BtnAdd_Run, $BtnRem_Run, $BtnExport_Run, $BtnClose_Run, $BtnDelete_Run)
$PageFirstInputs = @($TxtCases_Search, $TxtAdd_Cases, $TxtRem_Cases, $TxtExport_Cases, $TxtClose_Cases, $TxtDelete_Cases)

$script:CurrentPage = 0
$NavList.Add_SelectionChanged({
    $index = $NavList.SelectedIndex
    # Ctrl+click on the current page clears the selection; put it back
    if ($index -lt 0) { $NavList.SelectedIndex = $script:CurrentPage; return }
    $script:CurrentPage = $index
    for ($i = 0; $i -lt $Pages.Count; $i++) {
        $Pages[$i].Visibility = if ($i -eq $index) { 'Visible' } else { 'Collapsed' }
    }
    Set-Status ''
    # Focus the page's first box once it has been laid out, unless the user is moving through the list with the arrow keys
    $fromListKeys = $NavList.IsKeyboardFocusWithin -and ([System.Windows.Input.InputManager]::Current.MostRecentInputDevice -is [System.Windows.Input.KeyboardDevice])
    if (-not $fromListKeys) {
        $null = $window.Dispatcher.BeginInvoke([System.Windows.Threading.DispatcherPriority]::Input, [Action]{
            $box = $PageFirstInputs[$NavList.SelectedIndex]
            if ($box) { $null = $box.Focus() }
        })
    }
})

# ------------------ Grids ------------------
Function New-GridColumn {
    param([string]$Header, [string]$Width = 'Auto', [System.Windows.FrameworkElement]$Owner, [string]$ChipTemplate)
    if ($ChipTemplate) {
        $col = New-Object System.Windows.Controls.DataGridTemplateColumn
        $col.CellTemplate = $Owner.FindResource($ChipTemplate)
        $col.SortMemberPath = $Header
        $col.ClipboardContentBinding = New-Object System.Windows.Data.Binding($Header)   # template columns copy as blank otherwise
    } else {
        $col = New-Object System.Windows.Controls.DataGridTextColumn
        $col.Binding = New-Object System.Windows.Data.Binding($Header)
        $col.ElementStyle = $Owner.FindResource('CellText')
    }
    $col.Header = $Header
    $col.Width = (New-Object System.Windows.Controls.DataGridLengthConverter).ConvertFromInvariantString($Width)
    $col
}
# Columns: ordered list of name = width ('Auto' or a star width such as '2*')
Function Initialize-Grid {
    param([System.Windows.Controls.DataGrid]$Grid, [System.Collections.Specialized.OrderedDictionary]$Columns, [System.Windows.FrameworkElement]$Owner)
    $Grid.AutoGenerateColumns = $false
    $Grid.IsReadOnly = $true
    $Grid.CanUserAddRows = $false
    $Grid.SelectionMode = 'Extended'
    foreach ($name in $Columns.Keys) {
        $chip = switch ($name) { 'Result' { 'ResultChipTemplate' } 'Status' { 'StatusChipTemplate' } default { $null } }
        $Grid.Columns.Add((New-GridColumn -Header $name -Width $Columns[$name] -Owner $Owner -ChipTemplate $chip))
    }
}
$ResultColumns = [ordered]@{ Time = 'Auto'; Case = '2*'; Member = '2*'; Action = 'Auto'; Result = 'Auto'; Detail = '3*' }
$CaseColumns   = [ordered]@{ Name = '3*'; Type = 'Auto'; Status = 'Auto'; Created = 'Auto' }

# One results collection and summary line per page; the worker's Write-Result rows land in the active one
$ResultsByGrid = @{}
$SummaryByGrid = @{
    GridCases_Results = $SumCases; GridAdd_Results = $SumAdd; GridRem_Results = $SumRem
    GridExport_Results = $SumExport; GridClose_Results = $SumClose; GridDelete_Results = $SumDelete
}
foreach ($grid in @($GridCases_Results, $GridAdd_Results, $GridRem_Results, $GridExport_Results, $GridClose_Results, $GridDelete_Results)) {
    Initialize-Grid -Grid $grid -Columns $ResultColumns -Owner $window
    $items = New-Object 'System.Collections.ObjectModel.ObservableCollection[object]'
    $grid.ItemsSource = $items
    $ResultsByGrid[$grid.Name] = $items
}
Initialize-Grid -Grid $GridCases -Columns $CaseColumns -Owner $window

Function Get-ResultSummary {
    param($Results)
    $ok      = @($Results | Where-Object { $_.Result -eq 'Success' }).Count
    $failed  = @($Results | Where-Object { $_.Result -eq 'Failed' }).Count
    $skipped = @($Results | Where-Object { $_.Result -eq 'Skipped' }).Count
    $parts = @('{0} succeeded' -f $ok)
    if ($failed)  { $parts += '{0} failed' -f $failed }
    if ($skipped) { $parts += '{0} skipped' -f $skipped }
    [pscustomobject]@{ Text = ($parts -join ', '); Failed = $failed }
}

Function Save-Results {
    param([System.Windows.Controls.DataGrid]$Grid, [string]$Label)
    $items = $ResultsByGrid[$Grid.Name]
    if (-not $items -or $items.Count -eq 0) {
        [System.Windows.MessageBox]::Show('There are no results to save yet.','Save Results','OK','Information') | Out-Null
        return
    }
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = 'CSV files (*.csv)|*.csv'
    $dlg.InitialDirectory = $logDir
    $dlg.FileName = 'PurviewCaseTools_{0}_{1}.csv' -f $Label, (Get-Date -Format 'yyyyMMdd_HHmmss')
    if ($dlg.ShowDialog($window)) {
        $items | Select-Object Time, Case, Member, Action, Result, Detail |
            Export-Csv -NoTypeInformation -LiteralPath $dlg.FileName -Encoding UTF8
        Write-Log ("Saved {0} results to {1}" -f $items.Count, $dlg.FileName)
        Set-Status ('Saved {0}' -f [System.IO.Path]::GetFileName($dlg.FileName))
    }
}

# ------------------ Background worker ------------------
# One long-lived runspace owns the IPPS connection and runs all cmdlets. The UI thread only
# reads inputs, starts an action, and adds queued results to the grid while the action runs.
$Worker = [runspacefactory]::CreateRunspace($Host)   # share the console host so module warnings still show there
$Worker.ApartmentState = 'STA'          # interactive sign-in needs an STA thread
$Worker.ThreadOptions  = 'ReuseThread'  # keep the connection on the same thread between actions
$Worker.Open()
$Worker.SessionStateProxy.SetVariable('logFile',  $logFile)
$Worker.SessionStateProxy.SetVariable('logDir',   $logDir)
$Worker.SessionStateProxy.SetVariable('OutQueue', $OutQueue)
$Worker.SessionStateProxy.SetVariable('Shared',   $Shared)
$init = [powershell]::Create()
$init.Runspace = $Worker
$null = $init.AddScript("`$ErrorActionPreference = 'Stop'`r`n" + $WorkerFunctions.ToString()).Invoke()
$init.Dispose()

$script:Job = $null

Function Write-PendingOutput {
    param($Results, $Summary)
    $row = $null
    $added = $false
    while ($OutQueue.TryDequeue([ref]$row)) {
        if ($null -ne $Results) { $Results.Add($row); $added = $true }
    }
    if ($added -and $Summary) { $Summary.Text = (Get-ResultSummary $Results).Text }
}

# Polls the running action: streams its results and finishes up when it completes
$PollTimer = New-Object System.Windows.Threading.DispatcherTimer
$PollTimer.Interval = [TimeSpan]::FromMilliseconds(150)
$PollTimer.Add_Tick({
    $job = $script:Job
    if (-not $job) { $PollTimer.Stop(); return }
    $done = $job.Handle.IsCompleted
    Write-PendingOutput $job.Results $job.Summary
    Update-BusyProgress
    if (-not $done) { return }

    $PollTimer.Stop()
    $script:Job = $null
    $output = $null
    $failure = $null
    try { $output = $job.PS.EndInvoke($job.Handle) }
    catch {
        $failure = $_.Exception
        if ($failure -is [System.Management.Automation.MethodInvocationException] -and $failure.InnerException) { $failure = $failure.InnerException }
    }
    finally { $job.PS.Dispose() }

    Update-ConnectionText
    Hide-Busy; Set-UIBusy $false

    if ($failure) {
        Write-Log ("Action failed: {0}" -f $failure.Message) 'ERROR'
        [System.Windows.MessageBox]::Show($failure.Message,'Error','OK','Error') | Out-Null
        Set-Status 'Failed' 'Error'
        return
    }
    if ($null -ne $job.SuccessStatus) { Set-Status $job.SuccessStatus }
    elseif ($null -ne $job.Results) {
        $summary = Get-ResultSummary $job.Results
        if ($summary.Failed -gt 0) { Set-Status ('Done: {0}' -f $summary.Text) 'Error' }
        else { Set-Status ('Done: {0}' -f $summary.Text) }
    }
    else { Set-Status 'Done!' }

    # Runs after the UI is released, so it may open a dialog or start another action
    if ($job.OnSuccess) {
        try { & $job.OnSuccess $output }
        catch { [System.Windows.MessageBox]::Show($_.Exception.Message,'Error','OK','Error') | Out-Null }
    }
})

# Runs $Action in the worker runspace. $Action is re-parsed there, so it can only use
# its parameters and the functions in $WorkerFunctions, never UI controls.
# $OnSuccess runs on the UI thread with the action's output.
Function Start-CaseAction {
    param(
        [Parameter(Mandatory=$true)][scriptblock]$Action,
        [hashtable]$Arguments = @{},
        [System.Windows.Controls.DataGrid]$ResultsGrid,
        [AllowNull()][object]$SuccessStatus = $null,
        [scriptblock]$OnSuccess
    )
    $results = $null
    $summary = $null
    if ($ResultsGrid) {
        $results = $ResultsByGrid[$ResultsGrid.Name]; $results.Clear()
        $summary = $SummaryByGrid[$ResultsGrid.Name]; if ($summary) { $summary.Text = '' }
    }
    $Shared.Progress = $null
    $ps = [powershell]::Create()
    $ps.Runspace = $Worker
    $null = $ps.AddScript($Action.ToString(), $true).AddParameters($Arguments)   # local scope: no leftovers between actions

    $handle = $ps.BeginInvoke()
    Set-UIBusy $true; Show-Busy; Set-Status ''
    $script:Job = @{ PS = $ps; Handle = $handle; Results = $results; Summary = $summary; SuccessStatus = $SuccessStatus; OnSuccess = $OnSuccess }
    $PollTimer.Start()
}

# ------------------ Input checks shown as you type ------------------
$script:CaseCache = @()
$script:CasesLoaded = $false
$script:CaseNameSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

# 'a', 'b', 'c' and 2 more
Function Join-Preview {
    param([string[]]$Items, [int]$Max = 3)
    $text = (@($Items | Select-Object -First $Max | ForEach-Object { "'$_'" })) -join ', '
    if ($Items.Count -gt $Max) { $text += ' and {0} more' -f ($Items.Count - $Max) }
    $text
}

Function Set-Hint {
    param([System.Windows.Controls.TextBox]$Box, [System.Windows.Controls.TextBlock]$Hint, [string]$Text, [ValidateSet('Normal','Warning','Invalid')][string]$Kind = 'Normal')
    $Hint.Text = $Text
    $key = switch ($Kind) { 'Warning' { 'WarningText' } 'Invalid' { 'DangerText' } default { 'TextSecondary' } }
    $Hint.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, $key)
    $Box.Tag = if ($Kind -eq 'Normal') { $null } else { $Kind }
}

Function Update-CaseHint {
    param([System.Windows.Controls.TextBox]$Box, [System.Windows.Controls.TextBlock]$Hint)
    $cases = @(Parse-Cases -CasesMultiline $Box.Text)
    if ($cases.Count -eq 0) { Set-Hint $Box $Hint ''; return }
    $count = if ($cases.Count -eq 1) { '1 case' } else { '{0} cases' -f $cases.Count }
    if (-not $script:CasesLoaded) {
        Set-Hint $Box $Hint ('{0}. Connect to check the names against the case list.' -f $count)
        return
    }
    $unknown = @($cases | Where-Object { -not $script:CaseNameSet.Contains($_) })
    if ($unknown.Count -gt 0) { Set-Hint $Box $Hint ('{0}. Not in the case list: {1}' -f $count, (Join-Preview $unknown)) 'Warning' }
    else { Set-Hint $Box $Hint ('{0}, all found in the case list.' -f $count) }
}

Function Update-EmailHint {
    param([System.Windows.Controls.TextBox]$Box, [System.Windows.Controls.TextBlock]$Hint, [string]$EmptyText = '', [string]$InvalidNote = 'these will be skipped')
    $entries = @(Split-InputList $Box.Text)
    if ($entries.Count -eq 0) { Set-Hint $Box $Hint $EmptyText; return }
    $valid = @(Parse-Emails -EmailsMultiline $Box.Text)
    $invalid = @($entries | Where-Object { $_ -notmatch $EmailPattern } | Select-Object -Unique)
    $count = if ($valid.Count -eq 1) { '1 reviewer' } else { '{0} reviewers' -f $valid.Count }
    if ($invalid.Count -gt 0) { Set-Hint $Box $Hint ('{0}. Not valid email addresses, {1}: {2}' -f $count, $InvalidNote, (Join-Preview $invalid)) 'Invalid' }
    else { Set-Hint $Box $Hint $count }
}

Function Update-ReplacementHint {
    $text = $TxtRem_Replacement.Text.Trim()
    if ($text -and $text -notmatch $EmailPattern) {
        Set-Hint $TxtRem_Replacement $HintRem_Replacement 'The replacement does not look like an email address.' 'Invalid'
        $HintRem_Replacement.Visibility = 'Visible'
    } else {
        Set-Hint $TxtRem_Replacement $HintRem_Replacement ''
        $HintRem_Replacement.Visibility = 'Collapsed'
    }
}

$CaseHintFor = @{
    TxtAdd_Cases = $HintAdd_Cases; TxtRem_Cases = $HintRem_Cases; TxtExport_Cases = $HintExport_Cases
    TxtClose_Cases = $HintClose_Cases; TxtDelete_Cases = $HintDelete_Cases
}
$RemEmailsEmptyText = $HintRem_Emails.Text
Function Update-AllCaseHints {
    foreach ($name in $CaseHintFor.Keys) { Update-CaseHint (Get-Variable -Name $name -ValueOnly) $CaseHintFor[$name] }
}
foreach ($name in $CaseHintFor.Keys) {
    (Get-Variable -Name $name -ValueOnly).Add_TextChanged({ param($s, $e) Update-CaseHint $s $CaseHintFor[$s.Name] })
}
$TxtAdd_Emails.Add_TextChanged({ Update-EmailHint $TxtAdd_Emails $HintAdd_Emails })
$TxtRem_Emails.Add_TextChanged({ Update-EmailHint $TxtRem_Emails $HintRem_Emails $RemEmailsEmptyText 'fix these before running' })
$TxtRem_Replacement.Add_TextChanged({ Update-ReplacementHint })

# ------------------ Case list and picker ------------------
$script:AfterCaseLoad = $null

$LoadCasesAction = {
    Connect-Compliance
    $seen = @{}
    $loaded = 0
    foreach ($type in 'eDiscovery', 'AdvancedEdiscovery') {
        try { $cases = @(Get-ComplianceCase -CaseType $type -ErrorAction Stop) }
        catch { Write-Log ("Could not list {0} cases: {1}" -f $type, $_.Exception.Message) 'WARN'; continue }
        $loaded++
        foreach ($c in $cases) {
            $id = [string]$c.Identity
            if ($seen.ContainsKey($id)) { continue }
            $seen[$id] = $true
            $created = ''
            if ($c.CreatedDateTime) { $created = ([datetime]$c.CreatedDateTime).ToString('yyyy-MM-dd') }
            [pscustomobject]@{
                Name     = [string]$c.Name
                Type     = $(if ($type -eq 'AdvancedEdiscovery') { 'Premium' } else { 'Standard' })
                Status   = [string]$c.Status
                Created  = $created
                Identity = $id
            }
        }
    }
    if ($loaded -eq 0) { throw 'Could not list cases. Check the log for details.' }
}

Function Select-Cases {
    param([string]$Search, [bool]$IncludeClosed)
    $Search = "$Search".Trim()
    @($script:CaseCache | Where-Object {
        ($IncludeClosed -or $_.Status -notlike 'Closed*') -and
        (-not $Search -or $_.Name.IndexOf($Search, [StringComparison]::OrdinalIgnoreCase) -ge 0)
    } | Sort-Object Name)
}

Function Update-CasesGrid {
    $shown = @(Select-Cases -Search $TxtCases_Search.Text -IncludeClosed ([bool]$ChkCases_Closed.IsChecked))
    $GridCases.ItemsSource = $shown
    if ($script:CasesLoaded) {
        $TxtCases_Count.Text = '{0} of {1} cases shown' -f $shown.Count, $script:CaseCache.Count
    }
}

# Loads every case into the cache; $Then runs on the UI thread afterwards
Function Start-CaseLoad {
    param([scriptblock]$Then)
    $script:AfterCaseLoad = $Then
    Start-CaseAction -Action $LoadCasesAction -SuccessStatus '' -OnSuccess {
        param($out)
        $script:CaseCache = @($out)
        $script:CasesLoaded = $true
        $script:CaseNameSet.Clear()
        foreach ($c in $script:CaseCache) {
            if ($c.Name) { $null = $script:CaseNameSet.Add($c.Name) }
            if ($c.Identity) { $null = $script:CaseNameSet.Add($c.Identity) }
        }
        Update-CasesGrid
        Update-AllCaseHints
        Set-Status ('Loaded {0} cases' -f $script:CaseCache.Count)
        if ($script:AfterCaseLoad) { $next = $script:AfterCaseLoad; $script:AfterCaseLoad = $null; & $next }
    }
}

# Opens the picker and appends the chosen case names to $Target (one per line, no duplicates)
Function Show-CasePicker {
    param([System.Windows.Controls.TextBox]$Target)
    if (-not $script:CasesLoaded) {
        $script:PickerTarget = $Target
        Start-CaseLoad -Then { Show-CasePicker -Target $script:PickerTarget }
        return
    }
    # Picker controls are script-scoped so the event handlers below can always reach them
    $script:Picker = New-ThemedWindow $pickerXaml
    $script:Picker.Owner = $window
    Set-Theme $script:Picker
    $script:PickSearch = $script:Picker.FindName('TxtPick_Search')
    $script:PickClosed = $script:Picker.FindName('ChkPick_Closed')
    $script:PickGrid   = $script:Picker.FindName('GridPick')
    $script:PickCount  = $script:Picker.FindName('TxtPick_Count')
    Initialize-Grid -Grid $script:PickGrid -Columns $CaseColumns -Owner $script:Picker

    $refresh = {
        $shown = @(Select-Cases -Search $script:PickSearch.Text -IncludeClosed ([bool]$script:PickClosed.IsChecked))
        $script:PickGrid.ItemsSource = $shown
        $script:PickCount.Text = '{0} of {1} cases shown. Select several with Ctrl or Shift.' -f $shown.Count, $script:CaseCache.Count
    }
    & $refresh
    $script:PickSearch.Add_TextChanged($refresh)
    $script:PickClosed.Add_Checked($refresh)
    $script:PickClosed.Add_Unchecked($refresh)
    $script:Picker.FindName('BtnPick_Ok').Add_Click({ $script:Picker.DialogResult = $true })
    $script:PickGrid.Add_MouseDoubleClick({ if ($script:PickGrid.SelectedItem) { $script:Picker.DialogResult = $true } })
    $script:Picker.Add_ContentRendered({ $null = $script:PickSearch.Focus() })

    if ($script:Picker.ShowDialog() -and $script:PickGrid.SelectedItems.Count -gt 0) {
        $names = @(Parse-Cases -CasesMultiline $Target.Text) + @($script:PickGrid.SelectedItems | ForEach-Object { $_.Name })
        $Target.Text = (@($names | Select-Object -Unique) -join "`r`n")
    }
}

$TxtCases_Search.Add_TextChanged({ Update-CasesGrid })
$ChkCases_Closed.Add_Checked({ Update-CasesGrid })
$ChkCases_Closed.Add_Unchecked({ Update-CasesGrid })

# ------------------ Banner: Base64/DataURI/File Loader (robust) ------------------
Function Normalize-Base64 {
    param([Parameter(Mandatory=$true)][string]$Input)
    $s = $Input.Trim()
    $s = $s -replace '^(data:image\/[a-zA-Z0-9.+-]+;base64,)', ''
    $s = ($s -replace '\s', '')
    $s = $s.Replace('-', '+').Replace('_', '/')
    switch ($s.Length % 4) { 0{} 2{$s+='=='} 3{$s+='='} default{ throw "Invalid Base64 length (cannot fix padding automatically)." } }
    return $s
}
Function Set-HeaderBanner {
    param(
        [Parameter(Mandatory=$true)][string]$InputData,
        [int]$DecodePixelHeight = 80
    )
    try {
        # Base64 -> bytes OR file path
        if ($InputData.Length -lt 260 -and (Test-Path -LiteralPath $InputData -PathType Leaf)) {
            $bytes = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $InputData))
        } else {
            $b64 = $InputData.Trim() -replace '^(data:image\/png;base64,)', '' -replace '\s',''
            $bytes = [Convert]::FromBase64String($b64)
        }

        # Decode from memory; OnLoad reads the whole stream so it can be closed straight away
        $stream = New-Object System.IO.MemoryStream(,$bytes)
        try {
            $bmp = New-Object System.Windows.Media.Imaging.BitmapImage
            $bmp.BeginInit()
            $bmp.StreamSource = $stream
            if ($DecodePixelHeight -gt 0) { $bmp.DecodePixelHeight = $DecodePixelHeight }
            $bmp.CacheOption = 'OnLoad'
            $bmp.EndInit()
            $bmp.Freeze()
        }
        finally { $stream.Dispose() }

        $HeaderBanner.Source = $bmp
    }
    catch {
        $err = "Failed to load header banner: {0}" -f $_.Exception.Message
        Write-Log $err 'WARN'
        [System.Windows.MessageBox]::Show($err,'Banner Load Error','OK','Warning') | Out-Null
        $HeaderBanner.Source = $null
    }
}
# Paste your Base64 string between the here-string markers below (PNG or JPG). Data URI ok.
$bannerBase64 = @"
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sqakEEHUF77whYWCiueeew6PP/541g+XLl0azO/s2bP46le/ujC/DwJDpxbu7OzENtj5ferUKXz+858fHLcW58+fn/ENt4guf/iHf7iUoG8eynln61+OkQceeAB/9Ed/lN277lhlYxHjDQtmyo9NBwdTuF4r4yFfxEF8kli1sYHxZILReAyQY/MKIjHuyCtPpOZD1qykZKA8gpzCxIymLV8zkRB9z7CDWxaEsPAnMl+R60EmQAtByhJNBy1PGWu9b2mgDpczWnjRthBBkDKsibeXfwVzHRn4wAyrLddwXtJs/udIfMAExH7w3vMJesJwAkmjgdS3lJrzceqYNojgy3c9061PzD2bK1k/TFIlgxD4JD2vQhBhslW4wGkNvcQ0khz7lOraVhjlJNBQmsQ6qiDIBwAsTEBNGJ84gu177sDGqaMgIrRXdrH3/fcxfXcH/V6H0AuD642gAavsWQ3jbqHccXl/2XyDCCn6gND2CG0H3wnNCKC6RjOZYHzyGDPloxqQk/CCCiY89xcLOoRWEFNIY8oYKxTHtjjJtn1UrBnRtA08ToI6mBaBSBKKCGRulEGonfq113GWp9c5oWMs1VvrLkKoKNiRfgWBiE3xALOmxI7hPNK8Fo0jW3etrV0rpa4h8OmQfcuCPiIV3GhdOZBjD8vcXl4LeB6Ytg7MC+eqqCk1U3bsY0MrHcMiPCJZCyQHSc/jg8dJoWFFWm6+humSFOz89VZwn9Y9Na2FU/JKe4PUVcfljHmr0k3LTt3UhR71ZAMbx46i3txgrVdfCIttdibtGgZKl5Xoo/OMg46nmI3Mi7jEyLw7REFrrLHGdcbhhE8zk7o0ydNQyXHUZQY3N86dO5cxelZT50bh7Nmz2NnZwWOPPYZ7770X999/P+677z7883/+zwEA//7f//sY9/Tp03OFEYp/+k//abx+8803V/ZhBGGArQDrpZdewn333Yf7778f999/P+644w48/PDDGfP9+OOPz2iS/Ot//a/jdanZZPEP/sE/KG/hB3/wB8tbETavwwqNrNARwKHotCyee+45PPjgg/H3a6+9hocffjj29/333497770X9913H1566aUYbzKZ4Ld+67fib8W5c+cywVPZPzqGyryeffbZ+NvimWeeyU78e/PNN/HUU0/hjjvuiPkREV544YUowDl9+vSNF3wsQNmGnZ0dPP/8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
"@
Set-HeaderBanner -InputData $bannerBase64 -DecodePixelHeight 128

# ------------------ Button handlers ------------------
# Each handler validates input on the UI thread, then hands the cmdlet work to Start-CaseAction.
Function Show-InputError($message) {
    [System.Windows.MessageBox]::Show($message,'Input Error','OK','Error') | Out-Null
    Set-Status 'Failed' 'Error'
}
Function Get-CasesInput([System.Windows.Controls.TextBox]$Box) {
    $cases = @(Parse-Cases -CasesMultiline $Box.Text)
    if ($cases.Count -eq 0) { throw 'Please enter one or more case names / ECM references.' }
    [string[]]$cases
}

# Connect signs in (or re-checks the session) and loads the case list
$BtnConnect.Add_Click({ Start-CaseLoad })

$ThemeToggle.Add_Click({
    $script:ThemeMode = switch ($script:ThemeMode) { 'System' { 'Light' } 'Light' { 'Dark' } default { 'System' } }
    Set-Theme $window
})
$LinkLogs.Add_Click({
    try { [System.Diagnostics.Process]::Start($logDir) | Out-Null }
    catch { [System.Windows.MessageBox]::Show(("Could not open {0}: {1}" -f $logDir, $_.Exception.Message),'Open Logs','OK','Warning') | Out-Null }
})

# Picker and save buttons
$BtnAdd_Pick.Add_Click({ Show-CasePicker -Target $TxtAdd_Cases })
$BtnRem_Pick.Add_Click({ Show-CasePicker -Target $TxtRem_Cases })
$BtnExport_Pick.Add_Click({ Show-CasePicker -Target $TxtExport_Cases })
$BtnClose_Pick.Add_Click({ Show-CasePicker -Target $TxtClose_Cases })
$BtnDelete_Pick.Add_Click({ Show-CasePicker -Target $TxtDelete_Cases })

$BtnCases_Save.Add_Click({ Save-Results -Grid $GridCases_Results -Label 'ReopenCases' })
$BtnAdd_Save.Add_Click({ Save-Results -Grid $GridAdd_Results -Label 'AddReviewers' })
$BtnRem_Save.Add_Click({ Save-Results -Grid $GridRem_Results -Label 'RemoveReviewers' })
$BtnExport_Save.Add_Click({ Save-Results -Grid $GridExport_Results -Label 'ExportCasePermissions' })
$BtnClose_Save.Add_Click({ Save-Results -Grid $GridClose_Results -Label 'CloseCases' })
$BtnDelete_Save.Add_Click({ Save-Results -Grid $GridDelete_Results -Label 'DeleteCases' })

# Cases page
$BtnCases_Refresh.Add_Click({ Start-CaseLoad })

$BtnCases_Copy.Add_Click({
    $names = @($GridCases.SelectedItems | ForEach-Object { $_.Name })
    if ($names.Count -eq 0) { Show-InputError 'Select one or more cases first.'; return }
    [System.Windows.Clipboard]::SetText($names -join "`r`n")
    Set-Status ('Copied {0} case names' -f $names.Count)
})

$BtnCases_Reopen.Add_Click({
    $selected = @($GridCases.SelectedItems | Where-Object { $_.Status -like 'Closed*' })
    if ($selected.Count -eq 0) { Show-InputError 'Select one or more closed cases to reopen.'; return }
    $targets = @($selected | ForEach-Object { @{ Name = $_.Name; Identity = $_.Identity } })
    Start-CaseAction -ResultsGrid $GridCases_Results -Arguments @{ Targets = $targets } -OnSuccess { Start-CaseLoad } -Action {
        param([object[]]$Targets)
        Connect-Compliance
        $i = 0
        foreach ($t in $Targets) {
            Set-ActionProgress -Done $i -Total $Targets.Count; $i++
            try { Set-ComplianceCase -Identity $t.Identity -Reopen -Confirm:$false -ErrorAction Stop; Write-Result -Case $t.Name -Action 'Reopen case' -Result Success }
            catch { Write-Result -Case $t.Name -Action 'Reopen case' -Result Failed -Detail $_.Exception.Message }
        }
        Set-ActionProgress -Done $i -Total $Targets.Count
    }
})

$BtnAdd_Run.Add_Click({
    try {
        $cases = Get-CasesInput $TxtAdd_Cases
        $emails = @(Parse-Emails -EmailsMultiline $TxtAdd_Emails.Text); if ($emails.Count -eq 0) { throw 'Please enter at least one valid reviewer email.' }
    } catch { Show-InputError $_.Exception.Message; return }

    Start-CaseAction -ResultsGrid $GridAdd_Results -Arguments @{ Cases = $cases; Emails = [string[]]$emails } -Action {
        param([string[]]$Cases, [string[]]$Emails)
        Connect-Compliance
        $i = 0
        foreach ($case in $Cases) {
            Set-ActionProgress -Done $i -Total $Cases.Count; $i++
            foreach ($m in $Emails) {
                try { Add-ComplianceCaseMember -Case $case -Member $m -ErrorAction Stop; Write-Result -Case $case -Member $m -Action 'Add reviewer' -Result Success }
                catch { Write-Result -Case $case -Member $m -Action 'Add reviewer' -Result Failed -Detail $_.Exception.Message }
            }
        }
        Set-ActionProgress -Done $i -Total $Cases.Count
    }
})

$BtnExport_Run.Add_Click({
    try { $cases = Get-CasesInput $TxtExport_Cases } catch { Show-InputError $_.Exception.Message; return }

    Start-CaseAction -ResultsGrid $GridExport_Results -Arguments @{ Cases = $cases } -Action {
        param([string[]]$Cases)
        Connect-Compliance
        $i = 0
        foreach ($case in $Cases) {
            Set-ActionProgress -Done $i -Total $Cases.Count; $i++
            try {
                $outFile = Join-Path $logDir ("AdvancedDiscovery_CaseMembers_{0}.csv" -f (ConvertTo-SafeFileName $case))
                $members = @(Get-ComplianceCaseMember -Case $case -ErrorAction Stop | Select-Object Name, PrimarySmtpAddress)
                $members | Export-Csv -NoTypeInformation -LiteralPath $outFile -Encoding UTF8
                Write-Result -Case $case -Action 'Export case permissions' -Result Success -Detail ("{0} members -> {1}" -f $members.Count, $outFile)
            } catch { Write-Result -Case $case -Action 'Export case permissions' -Result Failed -Detail $_.Exception.Message }
        }
        Set-ActionProgress -Done $i -Total $Cases.Count
    }
})

$BtnRem_Run.Add_Click({
    try {
        $cases = Get-CasesInput $TxtRem_Cases
        $emails = @(Parse-Emails -EmailsMultiline $TxtRem_Emails.Text)
        # An empty box means "remove everyone", so a box of mistyped addresses must not fall through to that
        $invalid = @(Split-InputList $TxtRem_Emails.Text | Where-Object { $_ -notmatch $EmailPattern } | Select-Object -Unique)
        if ($invalid.Count -gt 0) { throw ('These reviewers to remove are not valid email addresses: {0}. Correct them, or clear the box to remove everyone except the replacement.' -f (Join-Preview $invalid)) }
        $replacement = $TxtRem_Replacement.Text.Trim()
        if (-not $replacement) { throw 'Please enter a replacement reviewer email.' }
    } catch { Show-InputError $_.Exception.Message; return }

    Start-CaseAction -ResultsGrid $GridRem_Results -Arguments @{ Cases = $cases; Emails = [string[]]$emails; Replacement = $replacement } -Action {
        param([string[]]$Cases, [string[]]$Emails, [string]$Replacement)
        Connect-Compliance

        $i = 0
        foreach ($case in $Cases) {
            Set-ActionProgress -Done $i -Total $Cases.Count; $i++

            # Ensure replacement is present first
            try {
                Add-ComplianceCaseMember -Case $case -Member $Replacement -ErrorAction SilentlyContinue
                Write-Result -Case $case -Member $Replacement -Action 'Add replacement' -Result Info -Detail 'Added, or already a member'
            }
            catch {
                Write-Result -Case $case -Member $Replacement -Action 'Add replacement' -Result Failed -Detail $_.Exception.Message
            }

            # Determine targets to remove
            $targets = $null
            if ($Emails -and $Emails.Count -gt 0) {
                # Targeted removal (exclude replacement if included)
                $targets = $Emails | Where-Object { $_ -and ($_ -ine $Replacement) }
            } else {
                # Remove ALL current members except the replacement
                try {
                    $targets = @(Get-CaseMemberEmails -Case $case -ExcludeEmail $Replacement)
                    if ($targets.Count -eq 0) {
                        Write-Result -Case $case -Action 'Remove reviewers' -Result Info -Detail 'No removable members found (after excluding replacement)'
                        continue
                    } else {
                        Write-Result -Case $case -Action 'Remove reviewers' -Result Info -Detail ('Removing all {0} current members except the replacement' -f $targets.Count)
                    }
                }
                catch {
                    Write-Result -Case $case -Action 'Remove reviewers' -Result Failed -Detail ("Failed to enumerate members: {0}" -f $_)
                    continue
                }
            }

            foreach ($m in $targets) {
                if ($m -ieq $Replacement) {
                    Write-Result -Case $case -Member $m -Action 'Remove reviewer' -Result Skipped -Detail 'Replacement reviewer is kept'
                    continue
                }
                try {
                    Remove-ComplianceCaseMember -Case $case -Member $m -Confirm:$false -ErrorAction Stop
                    Write-Result -Case $case -Member $m -Action 'Remove reviewer' -Result Success
                }
                catch {
                    Write-Result -Case $case -Member $m -Action 'Remove reviewer' -Result Failed -Detail $_.Exception.Message
                }
            }
        }
        Set-ActionProgress -Done $i -Total $Cases.Count
    }
})

$BtnClose_Run.Add_Click({
    try { $cases = Get-CasesInput $TxtClose_Cases } catch { Show-InputError $_.Exception.Message; return }

    Start-CaseAction -ResultsGrid $GridClose_Results -Arguments @{ Cases = $cases } -Action {
        param([string[]]$Cases)
        Connect-Compliance
        $i = 0
        foreach ($case in $Cases) {
            Set-ActionProgress -Done $i -Total $Cases.Count; $i++
            try { Set-ComplianceCase -Identity $case -Close -Confirm:$false -ErrorAction Stop; Write-Result -Case $case -Action 'Close case' -Result Success }
            catch { Write-Result -Case $case -Action 'Close case' -Result Failed -Detail $_.Exception.Message }
        }
        Set-ActionProgress -Done $i -Total $Cases.Count
    }
})

$BtnDelete_Run.Add_Click({
    $prompt = [System.Windows.MessageBox]::Show('This will DELETE the listed cases. This action is irreversible. Continue?','Confirm Delete','YesNo','Warning','No')
    if ($prompt -ne 'Yes') { return }

    try { $cases = Get-CasesInput $TxtDelete_Cases } catch { Show-InputError $_.Exception.Message; return }

    Start-CaseAction -ResultsGrid $GridDelete_Results -Arguments @{ Cases = $cases } -Action {
        param([string[]]$Cases)
        Connect-Compliance
        $i = 0
        foreach ($case in $Cases) {
            Set-ActionProgress -Done $i -Total $Cases.Count; $i++
            try { Remove-ComplianceCase -Identity $case -Confirm:$false -ErrorAction Stop; Write-Result -Case $case -Action 'Delete case' -Result Success }
            catch { Write-Result -Case $case -Action 'Delete case' -Result Failed -Detail $_.Exception.Message }
        }
        Set-ActionProgress -Done $i -Total $Cases.Count
    }
})

# ------------------ Keyboard shortcuts ------------------
# Ctrl+Enter runs the current page, F5 refreshes the case list, Ctrl+1 to Ctrl+6 switch pages
$window.Add_PreviewKeyDown({
    param($s, $e)
    # Ctrl without Alt, so AltGr (Ctrl+Alt) still types characters such as @ on non-US keyboards
    $mods = [System.Windows.Input.Keyboard]::Modifiers
    $ctrl = (($mods -band [System.Windows.Input.ModifierKeys]::Control) -eq [System.Windows.Input.ModifierKeys]::Control) -and
            (($mods -band [System.Windows.Input.ModifierKeys]::Alt) -ne [System.Windows.Input.ModifierKeys]::Alt)
    $key = [int]$e.Key
    if ($ctrl -and $key -eq [int][System.Windows.Input.Key]::Enter) {
        $index = $NavList.SelectedIndex
        if ($index -ge 0) { Invoke-ButtonClick $PageRunButtons[$index] }
        $e.Handled = $true
    }
    elseif ($key -eq [int][System.Windows.Input.Key]::F5) {
        Invoke-ButtonClick $BtnCases_Refresh
        $e.Handled = $true
    }
    elseif ($ctrl -and $key -ge [int][System.Windows.Input.Key]::D1 -and $key -le [int][System.Windows.Input.Key]::D6) {
        $NavList.SelectedIndex = $key - [int][System.Windows.Input.Key]::D1
        $e.Handled = $true
    }
})

# Closing mid-action stops the running pipeline rather than leaving it running unseen
$window.Add_Closing({
    param($s, $e)
    if ($script:Job) {
        $answer = [System.Windows.MessageBox]::Show('An action is still running. Stop it and close?','Action Running','YesNo','Warning')
        if ($answer -ne 'Yes') { $e.Cancel = $true; return }
        Write-Log 'Window closed while an action was running; stopping it.' 'WARN'
        $null = $script:Job.PS.BeginStop($null, $null)
    }
    Save-Settings
})

# ------------------ Show UI ------------------
$startPage = Restore-Settings (Read-Settings)
Set-Theme $window
Update-ConnectionText
$NavList.SelectedIndex = $startPage
$null = $window.ShowDialog()
try { $Worker.Dispose() } catch { }
