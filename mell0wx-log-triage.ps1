<#
.SYNOPSIS
    Windows Log Triage Tool - A PowerShell GUI for extracting and reviewing suspicious Windows event logs.

.DESCRIPTION
    This script provides a graphical interface to scan Windows, Sysmon, and PowerShell logs for potentially suspicious activity,
    filter and search through results, and export findings to CSV. It includes filtering by keyword, date range, and user.
    It requires administrative privileges and access to the relevant event logs.

.REQUIREMENTS
    - Windows PowerShell 5.1 or later
    - .NET Framework (for WinForms)
    - Run as Administrator for full log access
    - Sysmon installed and logging enabled

.AUTHOR
    mell0wx
#>
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Dark theme colors
$bgColor = [System.Drawing.Color]::FromArgb(18, 18, 18)
$fgColor = [System.Drawing.Color]::WhiteSmoke
$accentColor = [System.Drawing.Color]::FromArgb(40, 40, 40)

# Create Form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Windows Log Triage Tool"
$form.Size = New-Object System.Drawing.Size(900, 700)
$form.StartPosition = "CenterScreen"
$form.BackColor = $bgColor
$form.ForeColor = $fgColor
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

# Controls
function New-Label($text, $x, $y) {
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = $text
    $lbl.Location = New-Object System.Drawing.Point($x, $y)
    $lbl.AutoSize = $true
    $lbl.ForeColor = $fgColor
    return $lbl
}

function New-Textbox($x, $y, $width) {
    $txt = New-Object System.Windows.Forms.TextBox
    $txt.Location = New-Object System.Drawing.Point($x, $y)
    $txt.Size = New-Object System.Drawing.Size($width, 20)
    $txt.BackColor = $accentColor
    $txt.ForeColor = $fgColor
    return $txt
}

$searchLabel = New-Label "Search:" 10 10
$form.Controls.Add($searchLabel)
$searchBox = New-Textbox 65 8 200
$form.Controls.Add($searchBox)

$maxEventsLabel = New-Label "Max Events:" 700 10
$form.Controls.Add($maxEventsLabel)
$maxEventsBox = New-Textbox 780 8 70
$maxEventsBox.Text = "1000"
$form.Controls.Add($maxEventsBox)
$fromDateLabel = New-Label "From Date (yyyy-MM-dd):" 10 40
$form.Controls.Add($fromDateLabel)
$fromDateBox = New-Textbox 160 38 110
$form.Controls.Add($fromDateBox)

$toDateLabel = New-Label "To Date (yyyy-MM-dd):" 290 40
$form.Controls.Add($toDateLabel)
$toDateBox = New-Textbox 430 38 110
$form.Controls.Add($toDateBox)
$userLabel = New-Label "Username (optional):" 10 70
$form.Controls.Add($userLabel)
$userBox = New-Textbox 160 68 150
$form.Controls.Add($userBox)

# DataGridView
$grid = New-Object System.Windows.Forms.DataGridView
$grid.Location = New-Object System.Drawing.Point(10, 100)
$grid.Size = New-Object System.Drawing.Size(860, 480)
$grid.AutoSizeColumnsMode = 'Fill'
$grid.EnableHeadersVisualStyles = $false
$grid.BackgroundColor = $bgColor
$grid.DefaultCellStyle.BackColor = $bgColor
$grid.DefaultCellStyle.ForeColor = $fgColor
$grid.DefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
$grid.ColumnHeadersDefaultCellStyle.BackColor = $accentColor
$grid.ColumnHeadersDefaultCellStyle.ForeColor = $fgColor
$form.Controls.Add($grid)

# Buttons
$exportButton = New-Object System.Windows.Forms.Button
$exportButton.Text = "Export"
$exportButton.Location = New-Object System.Drawing.Point(10, 600)
$exportButton.Enabled = $false
$exportButton.BackColor = $accentColor
$exportButton.ForeColor = $fgColor
$form.Controls.Add($exportButton)

$scanButton = New-Object System.Windows.Forms.Button
$scanButton.Text = "Start Triage"
$scanButton.Location = New-Object System.Drawing.Point(750, 600)
$scanButton.BackColor = $accentColor
$scanButton.ForeColor = $fgColor
$form.Controls.Add($scanButton)

# File Dialog
$saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
$saveFileDialog.Filter = "CSV files (*.csv)|*.csv"
$saveFileDialog.Title = "Save Triage Output As"

# Global results
$script:rawEvents = @()

# Suspicious log event extraction
function Get-SuspiciousEvents {
    param(
        [int]$maxEvents = 1000,
        [string]$fromDate,
        [string]$toDate,
        [string]$userFilter
    )
    $events = @()
    $eventFilters = @(
        @{LogName="Security"; Ids=4624,4625,4672,4720,4698},
        @{LogName="Windows PowerShell"; Ids=4104},
        @{LogName="System"; Ids=7045},
        @{LogName="Microsoft-Windows-Sysmon/Operational"; Ids=1,3,11,13,15,22,23,24,25}
    )

    $startTime = if ($fromDate) { [datetime]::ParseExact($fromDate, 'yyyy-MM-dd', $null) } else { $null }
    $endTime = if ($toDate) { [datetime]::ParseExact($toDate, 'yyyy-MM-dd', $null) } else { $null }

    foreach ($filter in $eventFilters) {
        try {
            $entries = Get-WinEvent -FilterHashtable @{LogName=$filter.LogName; Id=$filter.Ids} -MaxEvents $maxEvents -ErrorAction SilentlyContinue
            foreach ($entry in $entries) {
                if ($startTime -and $entry.TimeCreated -lt $startTime) { continue }
                if ($endTime -and $entry.TimeCreated -gt $endTime) { continue }
                if ($userFilter) {
                    $userName = $null
                    if ($entry.Properties.Count -gt 0) {
                        # Try to extract user from event properties (common for Security logs)
                        foreach ($prop in $entry.Properties) {
                            if ($prop.Value -and $prop.Value.ToString().ToLower().Contains($userFilter.ToLower())) {
                                $userName = $prop.Value
                                break
                            }
                        }
                    }
                    if (-not $userName -and $entry.UserId) {
                        try {
                            $resolvedUser = (New-Object System.Security.Principal.SecurityIdentifier($entry.UserId)).Translate([System.Security.Principal.NTAccount]).Value
                            if ($resolvedUser.ToLower().Contains($userFilter.ToLower())) {
                                $userName = $resolvedUser
                            }
                        } catch {}
                    }
                    if (-not $userName) { continue }
                }

                $events += [PSCustomObject]@{
                    TimeCreated = $entry.TimeCreated
                    LogName     = $filter.LogName
                    EventID     = $entry.Id
                    Message     = ($entry.Message -replace "`r`n", " ") -replace '\s+', ' '
                }
            }
        } catch {
            Write-Warning "Could not read $($filter.LogName)"
        }
    }
    return $events
}
function Clear-GridDataSource {
    $grid.DataSource = $null
}

# Search filter
$searchBox.Add_TextChanged({
    $keyword = $searchBox.Text.ToLower()
    if ($script:rawEvents.Count -gt 0) {
        $filtered = $script:rawEvents | Where-Object {
            $_.Message.ToLower().Contains($keyword) -or
            $_.EventID.ToString().Contains($keyword) -or
            $_.LogName.ToLower().Contains($keyword)
        }
        if ($filtered) {
            $typedArray = New-Object System.Collections.ArrayList
            $filtered | ForEach-Object { [void]$typedArray.Add($_) }
            $grid.DataSource = $typedArray
        } else {
            Clear-GridDataSource
        }
    }
})

# Export click
$exportButton.Add_Click({
    if ($saveFileDialog.ShowDialog() -eq "OK") {
        $data = $grid.DataSource
        if ($null -eq $data -or $data.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("No data to export.")
            return
        }
        $array = @()
        foreach ($item in $data) { $array += $item }
        $array | Export-Csv -Path $saveFileDialog.FileName -NoTypeInformation
    }
})
$scanButton.Add_Click({
    $scanButton.Enabled = $false
    $exportButton.Enabled = $false
    $maxEvents = 1000
    $userMax = 0
    if (-not [int]::TryParse($maxEventsBox.Text, [ref]$userMax) -or $userMax -le 0) {
        [System.Windows.Forms.MessageBox]::Show("Please enter a valid positive integer for Max Events.")
        $scanButton.Enabled = $true
        return
    } else {
        $maxEvents = $userMax
    }

    $results = Get-SuspiciousEvents -maxEvents $maxEvents -fromDate $fromDateBox.Text -toDate $toDateBox.Text -userFilter $userBox.Text

    if (-not $results -or $results.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No suspicious logs found.")
        $script:rawEvents = @()
        Clear-GridDataSource
        $exportButton.Enabled = $false
        $scanButton.Enabled = $true
        return
    }

    $script:rawEvents = $results
    $typedArray = New-Object System.Collections.ArrayList
    $results | ForEach-Object { [void]$typedArray.Add($_) }
    $grid.DataSource = $typedArray
    $exportButton.Enabled = $true
    $scanButton.Enabled = $true
})

# Constant for grid horizontal margin (for maintainability)
$GRID_HORIZONTAL_MARGIN = 40

# Resize event to adjust controls dynamically
$form.Add_Resize({
    $formWidth = $form.ClientSize.Width
    $formHeight = $form.ClientSize.Height

    $searchBox.Width = [int][Math]::Max(100, $formWidth * 0.3)
    $searchLabel.Left = 10 # "Search:" label
    $searchBox.Left = $searchLabel.Left + $searchLabel.Width + 5

    $maxEventsBox.Left = $maxEventsLabel.Left + $maxEventsLabel.Width + 5

    $fromDateBox.Left = $fromDateLabel.Left + $fromDateLabel.Width + 5
    $toDateLabel.Left = $fromDateBox.Left + $fromDateBox.Width + 20 # "To Date" label
    $toDateBox.Left = $toDateLabel.Left + $toDateLabel.Width + 5

    # Adjust DataGridView
    $grid.Width = $formWidth - $GRID_HORIZONTAL_MARGIN # Use constant for margin
    $gridVerticalOffset = 220
    $grid.Height = $formHeight - $gridVerticalOffset
    $userBox.Width = [int][Math]::Min(200, $formWidth * 0.25)

    # Adjust Buttons
    $exportButton.Top = $formHeight - 80
    $scanButton.Top = $formHeight - 80
    $scanButton.Left = $formWidth - 150
})

# Show the form and start the message loop
$form.ShowDialog() | Out-Null
