<#
Purview-Case-Tools_v8
#>
[CmdletBinding()]
param()

# ------------------ Saved reviewer lists (edit here) ------------------
# Each line is one choice in the "Add from list" drop-down on the Add Reviewers page.
# Change the addresses or the list name, or add another line for another list.
$ReviewerLists = [ordered]@{
    'List1' = @('example1@email.com', 'example2@email.com')
    'List2' = @('example3@email.com', 'example4@email.com')
}

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

    <!-- Drop-down lists -->
    <Style x:Key="ComboToggle" TargetType="ToggleButton">
      <Setter Property="Focusable" Value="False"/>
      <Setter Property="IsTabStop" Value="False"/>
      <Setter Property="ClickMode" Value="Press"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ToggleButton">
            <Border Background="Transparent">
              <TextBlock HorizontalAlignment="Right" VerticalAlignment="Center" Margin="0,0,10,0" FontFamily="Segoe Fluent Icons, Segoe MDL2 Assets" FontSize="10" Text="&#xE70D;" Foreground="{DynamicResource TextSecondary}"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="ComboBox">
      <Setter Property="Foreground" Value="{DynamicResource TextPrimary}"/>
      <Setter Property="Background" Value="{DynamicResource InputBg}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource InputBorder}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="10,6,30,6"/>
      <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
      <Setter Property="ScrollViewer.HorizontalScrollBarVisibility" Value="Disabled"/>
      <Setter Property="ScrollViewer.VerticalScrollBarVisibility" Value="Auto"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ComboBox">
            <Grid x:Name="Root">
              <Border x:Name="Bd" CornerRadius="6" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" SnapsToDevicePixels="True"/>
              <ToggleButton Style="{StaticResource ComboToggle}" IsChecked="{Binding IsDropDownOpen, Mode=TwoWay, RelativeSource={RelativeSource TemplatedParent}}"/>
              <ContentPresenter IsHitTestVisible="False" Margin="{TemplateBinding Padding}" HorizontalAlignment="Left" VerticalAlignment="Center"
                                Content="{TemplateBinding SelectionBoxItem}" ContentTemplate="{TemplateBinding SelectionBoxItemTemplate}" ContentTemplateSelector="{TemplateBinding ItemTemplateSelector}"/>
              <Popup x:Name="PART_Popup" Placement="Bottom" AllowsTransparency="True" Focusable="False" PopupAnimation="Fade"
                     IsOpen="{Binding IsDropDownOpen, Mode=TwoWay, RelativeSource={RelativeSource TemplatedParent}}">
                <Border Margin="0,4,0,0" Padding="4" CornerRadius="6" MinWidth="{Binding ActualWidth, ElementName=Root}" MaxHeight="{TemplateBinding MaxDropDownHeight}"
                        Background="{DynamicResource CardBg}" BorderBrush="{DynamicResource CardBorder}" BorderThickness="1">
                  <ScrollViewer>
                    <ItemsPresenter KeyboardNavigation.DirectionalNavigation="Contained"/>
                  </ScrollViewer>
                </Border>
              </Popup>
            </Grid>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="BorderBrush" Value="{DynamicResource InputHoverBorder}"/>
              </Trigger>
              <Trigger Property="IsKeyboardFocusWithin" Value="True">
                <Setter TargetName="Bd" Property="BorderBrush" Value="{DynamicResource Accent}"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter TargetName="Root" Property="Opacity" Value="0.5"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="ComboBoxItem">
      <Setter Property="Foreground" Value="{DynamicResource TextPrimary}"/>
      <Setter Property="Padding" Value="8,6"/>
      <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ComboBoxItem">
            <Border x:Name="Bd" CornerRadius="4" Background="Transparent" Padding="{TemplateBinding Padding}" SnapsToDevicePixels="True">
              <ContentPresenter VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsSelected" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="{DynamicResource GridSelect}"/>
              </Trigger>
              <Trigger Property="IsHighlighted" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="{DynamicResource NavHover}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
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
        Title="CSO eDiscovery | Purview Case Management Tools" Height="800" Width="1120" MinHeight="640" MinWidth="900"
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

    <!-- Header: banner art (teal, or the drawn Neon art), title, connection and Connect button -->
    <Grid Grid.Row="0" Height="64" ClipToBounds="True">
      <Border x:Name="HeaderTeal" Background="#185951">
        <Image x:Name="HeaderBanner" Height="64" Stretch="Uniform" HorizontalAlignment="Left" RenderOptions.BitmapScalingMode="HighQuality" SnapsToDevicePixels="True"/>
      </Border>
      <Viewbox x:Name="HeaderNeon" Stretch="UniformToFill" Visibility="Collapsed">
        <Canvas Width="1200" Height="64">
          <Canvas.Background>
            <LinearGradientBrush StartPoint="0,0" EndPoint="1,0">
              <GradientStop Offset="0" Color="#3A0A2C"/>
              <GradientStop Offset="0.32" Color="#5E0E48"/>
              <GradientStop Offset="0.55" Color="#7A1A88"/>
              <GradientStop Offset="0.78" Color="#3E2AA8"/>
              <GradientStop Offset="1" Color="#1E4FD0"/>
            </LinearGradientBrush>
          </Canvas.Background>
          <Ellipse Canvas.Left="380" Canvas.Top="-70" Width="640" Height="132">
            <Ellipse.Fill><RadialGradientBrush><GradientStop Offset="0" Color="#C0FF3FC8"/><GradientStop Offset="1" Color="#00FF3FC8"/></RadialGradientBrush></Ellipse.Fill>
          </Ellipse>
          <Ellipse Canvas.Left="670" Canvas.Top="-42" Width="260" Height="68">
            <Ellipse.Fill><RadialGradientBrush><GradientStop Offset="0" Color="#8CFFB3F0"/><GradientStop Offset="1" Color="#00FFB3F0"/></RadialGradientBrush></Ellipse.Fill>
          </Ellipse>
          <Ellipse Canvas.Left="890" Canvas.Top="12" Width="480" Height="116">
            <Ellipse.Fill><RadialGradientBrush><GradientStop Offset="0" Color="#8C38BDF8"/><GradientStop Offset="1" Color="#0038BDF8"/></RadialGradientBrush></Ellipse.Fill>
          </Ellipse>
          <Canvas>
            <Canvas.Effect><BlurEffect Radius="8"/></Canvas.Effect>
            <Rectangle Canvas.Left="400" Canvas.Top="89.0" Width="380" Height="18" RadiusX="9.0" RadiusY="9.0" Opacity="0.55" RenderTransformOrigin="0,0.5">
              <Rectangle.RenderTransform><RotateTransform Angle="-33"/></Rectangle.RenderTransform>
              <Rectangle.Fill><LinearGradientBrush StartPoint="0,0.5" EndPoint="1,0.5"><GradientStop Offset="0" Color="#00B0207A"/><GradientStop Offset="0.55" Color="#B0207A"/><GradientStop Offset="1" Color="#00B0207A"/></LinearGradientBrush></Rectangle.Fill>
            </Rectangle>
            <Rectangle Canvas.Left="480" Canvas.Top="81.0" Width="440" Height="26" RadiusX="13.0" RadiusY="13.0" Opacity="0.6" RenderTransformOrigin="0,0.5">
              <Rectangle.RenderTransform><RotateTransform Angle="-33"/></Rectangle.RenderTransform>
              <Rectangle.Fill><LinearGradientBrush StartPoint="0,0.5" EndPoint="1,0.5"><GradientStop Offset="0" Color="#00E83FB8"/><GradientStop Offset="0.55" Color="#E83FB8"/><GradientStop Offset="1" Color="#00E83FB8"/></LinearGradientBrush></Rectangle.Fill>
            </Rectangle>
            <Rectangle Canvas.Left="560" Canvas.Top="92.0" Width="480" Height="16" RadiusX="8.0" RadiusY="8.0" Opacity="0.7" RenderTransformOrigin="0,0.5">
              <Rectangle.RenderTransform><RotateTransform Angle="-33"/></Rectangle.RenderTransform>
              <Rectangle.Fill><LinearGradientBrush StartPoint="0,0.5" EndPoint="1,0.5"><GradientStop Offset="0" Color="#00FF5BD6"/><GradientStop Offset="0.55" Color="#FF5BD6"/><GradientStop Offset="1" Color="#00FF5BD6"/></LinearGradientBrush></Rectangle.Fill>
            </Rectangle>
            <Rectangle Canvas.Left="640" Canvas.Top="81.0" Width="420" Height="30" RadiusX="15.0" RadiusY="15.0" Opacity="0.45" RenderTransformOrigin="0,0.5">
              <Rectangle.RenderTransform><RotateTransform Angle="-33"/></Rectangle.RenderTransform>
              <Rectangle.Fill><LinearGradientBrush StartPoint="0,0.5" EndPoint="1,0.5"><GradientStop Offset="0" Color="#00C13BE0"/><GradientStop Offset="0.55" Color="#C13BE0"/><GradientStop Offset="1" Color="#00C13BE0"/></LinearGradientBrush></Rectangle.Fill>
            </Rectangle>
            <Rectangle Canvas.Left="720" Canvas.Top="97.0" Width="440" Height="14" RadiusX="7.0" RadiusY="7.0" Opacity="0.6" RenderTransformOrigin="0,0.5">
              <Rectangle.RenderTransform><RotateTransform Angle="-33"/></Rectangle.RenderTransform>
              <Rectangle.Fill><LinearGradientBrush StartPoint="0,0.5" EndPoint="1,0.5"><GradientStop Offset="0" Color="#00FF7AE0"/><GradientStop Offset="0.55" Color="#FF7AE0"/><GradientStop Offset="1" Color="#00FF7AE0"/></LinearGradientBrush></Rectangle.Fill>
            </Rectangle>
            <Rectangle Canvas.Left="800" Canvas.Top="90.0" Width="360" Height="20" RadiusX="10.0" RadiusY="10.0" Opacity="0.45" RenderTransformOrigin="0,0.5">
              <Rectangle.RenderTransform><RotateTransform Angle="-33"/></Rectangle.RenderTransform>
              <Rectangle.Fill><LinearGradientBrush StartPoint="0,0.5" EndPoint="1,0.5"><GradientStop Offset="0" Color="#00E040FB"/><GradientStop Offset="0.55" Color="#E040FB"/><GradientStop Offset="1" Color="#00E040FB"/></LinearGradientBrush></Rectangle.Fill>
            </Rectangle>
            <Rectangle Canvas.Left="890" Canvas.Top="94.0" Width="400" Height="20" RadiusX="10.0" RadiusY="10.0" Opacity="0.6" RenderTransformOrigin="0,0.5">
              <Rectangle.RenderTransform><RotateTransform Angle="-33"/></Rectangle.RenderTransform>
              <Rectangle.Fill><LinearGradientBrush StartPoint="0,0.5" EndPoint="1,0.5"><GradientStop Offset="0" Color="#003B82F6"/><GradientStop Offset="0.55" Color="#3B82F6"/><GradientStop Offset="1" Color="#003B82F6"/></LinearGradientBrush></Rectangle.Fill>
            </Rectangle>
            <Rectangle Canvas.Left="980" Canvas.Top="94.0" Width="340" Height="12" RadiusX="6.0" RadiusY="6.0" Opacity="0.7" RenderTransformOrigin="0,0.5">
              <Rectangle.RenderTransform><RotateTransform Angle="-33"/></Rectangle.RenderTransform>
              <Rectangle.Fill><LinearGradientBrush StartPoint="0,0.5" EndPoint="1,0.5"><GradientStop Offset="0" Color="#0038BDF8"/><GradientStop Offset="0.55" Color="#38BDF8"/><GradientStop Offset="1" Color="#0038BDF8"/></LinearGradientBrush></Rectangle.Fill>
            </Rectangle>
            <Rectangle Canvas.Left="1060" Canvas.Top="98.0" Width="300" Height="16" RadiusX="8.0" RadiusY="8.0" Opacity="0.5" RenderTransformOrigin="0,0.5">
              <Rectangle.RenderTransform><RotateTransform Angle="-33"/></Rectangle.RenderTransform>
              <Rectangle.Fill><LinearGradientBrush StartPoint="0,0.5" EndPoint="1,0.5"><GradientStop Offset="0" Color="#0060A5FA"/><GradientStop Offset="0.55" Color="#60A5FA"/><GradientStop Offset="1" Color="#0060A5FA"/></LinearGradientBrush></Rectangle.Fill>
            </Rectangle>
          </Canvas>
          <Rectangle Canvas.Left="470" Canvas.Top="69.4" Width="120" Height="1.2" Opacity="0.75" RenderTransformOrigin="0,0.5">
            <Rectangle.RenderTransform><RotateTransform Angle="-33"/></Rectangle.RenderTransform>
            <Rectangle.Fill><LinearGradientBrush StartPoint="0,0.5" EndPoint="1,0.5"><GradientStop Offset="0" Color="#00FF9BEA"/><GradientStop Offset="0.7" Color="#FF9BEA"/><GradientStop Offset="1" Color="#00FF9BEA"/></LinearGradientBrush></Rectangle.Fill>
          </Rectangle>
          <Rectangle Canvas.Left="560" Canvas.Top="57.4" Width="150" Height="1.2" Opacity="0.8" RenderTransformOrigin="0,0.5">
            <Rectangle.RenderTransform><RotateTransform Angle="-33"/></Rectangle.RenderTransform>
            <Rectangle.Fill><LinearGradientBrush StartPoint="0,0.5" EndPoint="1,0.5"><GradientStop Offset="0" Color="#00F0ABFC"/><GradientStop Offset="0.7" Color="#F0ABFC"/><GradientStop Offset="1" Color="#00F0ABFC"/></LinearGradientBrush></Rectangle.Fill>
          </Rectangle>
          <Rectangle Canvas.Left="640" Canvas.Top="75.5" Width="110" Height="1" Opacity="0.7" RenderTransformOrigin="0,0.5">
            <Rectangle.RenderTransform><RotateTransform Angle="-33"/></Rectangle.RenderTransform>
            <Rectangle.Fill><LinearGradientBrush StartPoint="0,0.5" EndPoint="1,0.5"><GradientStop Offset="0" Color="#00FFC2F2"/><GradientStop Offset="0.7" Color="#FFC2F2"/><GradientStop Offset="1" Color="#00FFC2F2"/></LinearGradientBrush></Rectangle.Fill>
          </Rectangle>
          <Rectangle Canvas.Left="700" Canvas.Top="39.5" Width="90" Height="1" Opacity="0.6" RenderTransformOrigin="0,0.5">
            <Rectangle.RenderTransform><RotateTransform Angle="-33"/></Rectangle.RenderTransform>
            <Rectangle.Fill><LinearGradientBrush StartPoint="0,0.5" EndPoint="1,0.5"><GradientStop Offset="0" Color="#00FF9BEA"/><GradientStop Offset="0.7" Color="#FF9BEA"/><GradientStop Offset="1" Color="#00FF9BEA"/></LinearGradientBrush></Rectangle.Fill>
          </Rectangle>
          <Rectangle Canvas.Left="760" Canvas.Top="69.3" Width="160" Height="1.4" Opacity="0.75" RenderTransformOrigin="0,0.5">
            <Rectangle.RenderTransform><RotateTransform Angle="-33"/></Rectangle.RenderTransform>
            <Rectangle.Fill><LinearGradientBrush StartPoint="0,0.5" EndPoint="1,0.5"><GradientStop Offset="0" Color="#00FBCFE8"/><GradientStop Offset="0.7" Color="#FBCFE8"/><GradientStop Offset="1" Color="#00FBCFE8"/></LinearGradientBrush></Rectangle.Fill>
          </Rectangle>
          <Rectangle Canvas.Left="830" Canvas.Top="47.5" Width="100" Height="1" Opacity="0.6" RenderTransformOrigin="0,0.5">
            <Rectangle.RenderTransform><RotateTransform Angle="-33"/></Rectangle.RenderTransform>
            <Rectangle.Fill><LinearGradientBrush StartPoint="0,0.5" EndPoint="1,0.5"><GradientStop Offset="0" Color="#00F0ABFC"/><GradientStop Offset="0.7" Color="#F0ABFC"/><GradientStop Offset="1" Color="#00F0ABFC"/></LinearGradientBrush></Rectangle.Fill>
          </Rectangle>
          <Rectangle Canvas.Left="360" Canvas.Top="61.5" Width="70" Height="1" Opacity="0.5" RenderTransformOrigin="0,0.5">
            <Rectangle.RenderTransform><RotateTransform Angle="-33"/></Rectangle.RenderTransform>
            <Rectangle.Fill><LinearGradientBrush StartPoint="0,0.5" EndPoint="1,0.5"><GradientStop Offset="0" Color="#00E879C8"/><GradientStop Offset="0.7" Color="#E879C8"/><GradientStop Offset="1" Color="#00E879C8"/></LinearGradientBrush></Rectangle.Fill>
          </Rectangle>
          <Rectangle Canvas.Left="900" Canvas.Top="83.2" Width="140" Height="1.6" Opacity="0.8" RenderTransformOrigin="0,0.5">
            <Rectangle.RenderTransform><RotateTransform Angle="-33"/></Rectangle.RenderTransform>
            <Rectangle.Fill><LinearGradientBrush StartPoint="0,0.5" EndPoint="1,0.5"><GradientStop Offset="0" Color="#0067E8F9"/><GradientStop Offset="0.7" Color="#67E8F9"/><GradientStop Offset="1" Color="#0067E8F9"/></LinearGradientBrush></Rectangle.Fill>
          </Rectangle>
          <Rectangle Canvas.Left="960" Canvas.Top="88.9" Width="190" Height="2.2" Opacity="0.85" RenderTransformOrigin="0,0.5">
            <Rectangle.RenderTransform><RotateTransform Angle="-33"/></Rectangle.RenderTransform>
            <Rectangle.Fill><LinearGradientBrush StartPoint="0,0.5" EndPoint="1,0.5"><GradientStop Offset="0" Color="#00A5F3FC"/><GradientStop Offset="0.7" Color="#A5F3FC"/><GradientStop Offset="1" Color="#00A5F3FC"/></LinearGradientBrush></Rectangle.Fill>
          </Rectangle>
          <Rectangle Canvas.Left="1040" Canvas.Top="94.7" Width="200" Height="2.6" Opacity="0.9" RenderTransformOrigin="0,0.5">
            <Rectangle.RenderTransform><RotateTransform Angle="-33"/></Rectangle.RenderTransform>
            <Rectangle.Fill><LinearGradientBrush StartPoint="0,0.5" EndPoint="1,0.5"><GradientStop Offset="0" Color="#0067E8F9"/><GradientStop Offset="0.7" Color="#67E8F9"/><GradientStop Offset="1" Color="#0067E8F9"/></LinearGradientBrush></Rectangle.Fill>
          </Rectangle>
          <Rectangle Canvas.Left="1090" Canvas.Top="79.3" Width="150" Height="1.4" Opacity="0.8" RenderTransformOrigin="0,0.5">
            <Rectangle.RenderTransform><RotateTransform Angle="-33"/></Rectangle.RenderTransform>
            <Rectangle.Fill><LinearGradientBrush StartPoint="0,0.5" EndPoint="1,0.5"><GradientStop Offset="0" Color="#0060A5FA"/><GradientStop Offset="0.7" Color="#60A5FA"/><GradientStop Offset="1" Color="#0060A5FA"/></LinearGradientBrush></Rectangle.Fill>
          </Rectangle>
          <Rectangle Canvas.Left="1140" Canvas.Top="91.1" Width="120" Height="1.8" Opacity="0.85" RenderTransformOrigin="0,0.5">
            <Rectangle.RenderTransform><RotateTransform Angle="-33"/></Rectangle.RenderTransform>
            <Rectangle.Fill><LinearGradientBrush StartPoint="0,0.5" EndPoint="1,0.5"><GradientStop Offset="0" Color="#00A5F3FC"/><GradientStop Offset="0.7" Color="#A5F3FC"/><GradientStop Offset="1" Color="#00A5F3FC"/></LinearGradientBrush></Rectangle.Fill>
          </Rectangle>
          <Rectangle Canvas.Left="990" Canvas.Top="49.5" Width="90" Height="1" Opacity="0.6" RenderTransformOrigin="0,0.5">
            <Rectangle.RenderTransform><RotateTransform Angle="-33"/></Rectangle.RenderTransform>
            <Rectangle.Fill><LinearGradientBrush StartPoint="0,0.5" EndPoint="1,0.5"><GradientStop Offset="0" Color="#0093C5FD"/><GradientStop Offset="0.7" Color="#93C5FD"/><GradientStop Offset="1" Color="#0093C5FD"/></LinearGradientBrush></Rectangle.Fill>
          </Rectangle>
          <Ellipse Canvas.Left="298.4" Canvas.Top="12.4" Width="3.2" Height="3.2" Fill="#FFFFFF" Opacity="0.6"/>
          <Ellipse Canvas.Left="350.8" Canvas.Top="42.8" Width="2.4" Height="2.4" Fill="#FFFFFF" Opacity="0.5"/>
          <Ellipse Canvas.Left="413.6" Canvas.Top="20.6" Width="2.8" Height="2.8" Fill="#FFFFFF" Opacity="0.6"/>
          <Ellipse Canvas.Left="528.2" Canvas.Top="8.2" Width="3.6" Height="3.6" Fill="#FFFFFF" Opacity="0.8"/>
          <Ellipse Canvas.Left="573.8" Canvas.Top="48.8" Width="2.4" Height="2.4" Fill="#FFFFFF" Opacity="0.6"/>
          <Ellipse Canvas.Left="653.4" Canvas.Top="24.4" Width="3.2" Height="3.2" Fill="#FFFFFF" Opacity="0.7"/>
          <Ellipse Canvas.Left="718.6" Canvas.Top="52.6" Width="2.8" Height="2.8" Fill="#FFFFFF" Opacity="0.6"/>
          <Ellipse Canvas.Left="843.2" Canvas.Top="16.2" Width="3.6" Height="3.6" Fill="#FFFFFF" Opacity="0.8"/>
          <Ellipse Canvas.Left="878.8" Canvas.Top="38.8" Width="2.4" Height="2.4" Fill="#FFFFFF" Opacity="0.6"/>
          <Ellipse Canvas.Left="933.4" Canvas.Top="10.4" Width="3.2" Height="3.2" Fill="#FFFFFF" Opacity="0.7"/>
          <Ellipse Canvas.Left="998.8" Canvas.Top="28.8" Width="2.4" Height="2.4" Fill="#FFFFFF" Opacity="0.6"/>
          <Ellipse Canvas.Left="1058.2" Canvas.Top="14.2" Width="3.6" Height="3.6" Fill="#FFFFFF" Opacity="0.8"/>
          <Ellipse Canvas.Left="1118.6" Canvas.Top="38.6" Width="2.8" Height="2.8" Fill="#FFFFFF" Opacity="0.7"/>
          <Ellipse Canvas.Left="1168.8" Canvas.Top="8.8" Width="2.4" Height="2.4" Fill="#FFFFFF" Opacity="0.6"/>
          <Ellipse Canvas.Left="238.8" Canvas.Top="28.8" Width="2.4" Height="2.4" Fill="#FFFFFF" Opacity="0.4"/>
          <Ellipse Canvas.Left="159" Canvas.Top="49" Width="2" Height="2" Fill="#FFFFFF" Opacity="0.35"/>
        </Canvas>
      </Viewbox>
      <DockPanel>
        <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center" Margin="0,0,16,0">
          <Border CornerRadius="12" Background="#33000000" Padding="10,5" Margin="0,0,12,0" VerticalAlignment="Center">
            <StackPanel Orientation="Horizontal">
              <Ellipse x:Name="ConnDot" Width="8" Height="8" Margin="0,0,8,0" VerticalAlignment="Center" Fill="#9CA3AF"/>
              <TextBlock x:Name="TxtConn" Text="Not connected" Foreground="#FFFFFF" VerticalAlignment="Center" MaxWidth="320" TextTrimming="CharacterEllipsis"/>
            </StackPanel>
          </Border>
          <Button x:Name="BtnConnect" Style="{StaticResource HeaderButton}" Tag="&#xE703;" Content="Connect" ToolTip="Sign in to Security &amp; Compliance and load the case list"/>
        </StackPanel>
        <TextBlock Margin="24,0,16,0" VerticalAlignment="Center" FontSize="20" Foreground="#FFFFFF" TextTrimming="CharacterEllipsis"><Run Text="CSO eDiscovery" FontWeight="SemiBold"/><Run Text="  |  " Foreground="#B3FFFFFF"/><Run Text="Purview Case Management Tools"/></TextBlock>
      </DockPanel>
    </Grid>

    <Grid Grid.Row="1">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="232"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>

      <!-- Navigation -->
      <Border Grid.Column="0" Background="{DynamicResource NavBg}" BorderBrush="{DynamicResource CardBorder}" BorderThickness="0,0,1,0">
        <DockPanel>
          <StackPanel DockPanel.Dock="Bottom" Margin="8,8,8,12">
            <Button x:Name="ThemeToggle" Style="{StaticResource SubtleButton}" Tag="&#xE790;" Content="Theme: System" HorizontalContentAlignment="Left" ToolTip="Switch between System, Light, Dark and Neon"/>
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
                <DockPanel Margin="0,10,0,0">
                  <TextBlock DockPanel.Dock="Left" Text="Add from list" Style="{StaticResource FieldLabel}" Margin="0,0,10,0" VerticalAlignment="Center"/>
                  <Button x:Name="BtnAdd_List" DockPanel.Dock="Right" Style="{StaticResource SubtleButton}" Tag="&#xE710;" Content="Add" Padding="8,3" Margin="8,0,0,0" ToolTip="Add this list's addresses to the reviewers above"/>
                  <ComboBox x:Name="CmbAdd_List"/>
                </DockPanel>
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
    # Magenta-to-blue scheme that goes with the drawn Neon header
    Neon = @{
        WindowBg = '#140A22'; NavBg = '#1B0F2E'; StatusBg = '#1B0F2E'
        CardBg = '#21133A'; CardBorder = '#3A2560'
        TextPrimary = '#F4EEFF'; TextSecondary = '#B9A8DC'
        Accent = '#FF4FD8'; AccentText = '#2B0626'
        DangerBg = '#B4234A'; DangerText = '#FF8FA8'; WarningText = '#FFD166'; SuccessText = '#6EE7B7'
        InputBg = '#1A0F2D'; InputBorder = '#4A3275'; InputHoverBorder = '#6E4FA8'
        ButtonBg = '#2A1A47'; ButtonBorder = '#4A3275'
        HoverOverlay = '#14FFFFFF'; PressedOverlay = '#24FFFFFF'; FocusBorder = '#F4EEFF'
        GridHeaderBg = '#1E1235'; GridLine = '#33214F'; GridAlt = '#25173F'; GridSelect = '#3E1F6E'
        NavHover = '#2A1A45'; NavSelected = '#33205A'
        ChipSuccessBg = '#0B3B2E'; ChipSuccessFg = '#6EE7B7'
        ChipFailedBg  = '#4C0F2A'; ChipFailedFg  = '#FF8FA8'
        ChipSkippedBg = '#4A3108'; ChipSkippedFg = '#FFD166'
        ChipInfoBg    = '#2E2350'; ChipInfoFg    = '#D6CCF5'
    }
}
$script:ThemeMode = 'System'   # System, Light, Dark or Neon

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
        # ::new rather than New-Object: New-Object wraps the brush in a PSObject, and the
        # resource dictionary would store that wrapper, which WPF rejects as a Brush
        $brush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color][System.Windows.Media.ColorConverter]::ConvertFromString($palette[$key]))
        $brush.Freeze()
        $Target.Resources[$key] = $brush
    }
    # The slim scroll bars have no arrow buttons; WPF sizes the smallest thumb at half this value
    $Target.Resources[[System.Windows.SystemParameters]::VerticalScrollBarButtonHeightKey] = [double]40
    $Target.Resources[[System.Windows.SystemParameters]::HorizontalScrollBarButtonWidthKey] = [double]40
    if ($Target -eq $window) {
        $HeaderNeon.Visibility = if ($name -eq 'Neon') { 'Visible' } else { 'Collapsed' }
        $HeaderTeal.Visibility = if ($name -eq 'Neon') { 'Collapsed' } else { 'Visible' }
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
    if ($Settings.Theme -in 'System', 'Light', 'Dark', 'Neon') { $script:ThemeMode = [string]$Settings.Theme }
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
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
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
    $script:ThemeMode = switch ($script:ThemeMode) { 'System' { 'Light' } 'Light' { 'Dark' } 'Dark' { 'Neon' } default { 'System' } }
    Set-Theme $window
})
$LinkLogs.Add_Click({
    try { [System.Diagnostics.Process]::Start($logDir) | Out-Null }
    catch { [System.Windows.MessageBox]::Show(("Could not open {0}: {1}" -f $logDir, $_.Exception.Message),'Open Logs','OK','Warning') | Out-Null }
})

# Saved reviewer lists ($ReviewerLists at the top of the script) on the Add Reviewers page
foreach ($listName in $ReviewerLists.Keys) { [void]$CmbAdd_List.Items.Add([string]$listName) }
if ($CmbAdd_List.Items.Count -gt 0) { $CmbAdd_List.SelectedIndex = 0 } else { $CmbAdd_List.IsEnabled = $false }

Function Get-ReviewerList([string]$Name) {
    @(foreach ($email in @($ReviewerLists[$Name])) { $email = ([string]$email).Trim(); if ($email) { $email } })
}
Function Update-ReviewerListToolTip {
    $name = [string]$CmbAdd_List.SelectedItem
    $members = @(Get-ReviewerList $name)
    $CmbAdd_List.ToolTip = if (-not $name) { $null } elseif ($members.Count -gt 0) { $members -join "`n" } else { 'This list is empty' }
}
$CmbAdd_List.Add_SelectionChanged({ Update-ReviewerListToolTip })
Update-ReviewerListToolTip

# Appends the list's addresses that aren't in the reviewers box yet
$BtnAdd_List.Add_Click({
    $name = [string]$CmbAdd_List.SelectedItem
    if (-not $name) { return }
    $members = @(Get-ReviewerList $name)
    if ($members.Count -eq 0) { Set-Status ('{0} is empty. Add addresses to it at the top of the script.' -f $name) 'Neutral'; return }
    $current = @(Split-InputList $TxtAdd_Emails.Text)
    $new = [System.Collections.Generic.List[string]]::new()
    foreach ($email in $members) {
        if ($current -notcontains $email -and $new -notcontains $email) { $new.Add($email) }
    }
    if ($new.Count -eq 0) { Set-Status ('Everyone in {0} is already in the reviewers box' -f $name) 'Neutral'; return }
    $text = $TxtAdd_Emails.Text.TrimEnd()
    $added = $new -join "`r`n"
    $TxtAdd_Emails.Text = if ($text) { $text + "`r`n" + $added } else { $added }
    $TxtAdd_Emails.CaretIndex = $TxtAdd_Emails.Text.Length
    $TxtAdd_Emails.ScrollToEnd()
    $noun = if ($new.Count -eq 1) { 'address' } else { 'addresses' }
    Set-Status ('Added {0} {1} from {2}' -f $new.Count, $noun, $name) 'Neutral'
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
