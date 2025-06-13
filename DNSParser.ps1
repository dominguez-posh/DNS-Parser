# Show an Open File Dialog and return the file selected by the user.
function Read-OpenFileDialog([string]$InitialDirectory, [switch]$AllowMultiSelect)
{
Add-Type -AssemblyName System.Windows.Forms
$openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
$openFileDialog.initialDirectory = $InitialDirectory
$openFileDialog.filter = "All files (*.*)| *.*"
if ($AllowMultiSelect) { $openFileDialog.MultiSelect = $true }
$openFileDialog.ShowDialog() > $null
if ($allowMultiSelect) { return $openFileDialog } else { return $openFileDialog }
}

$FileNames = Read-OpenFileDialog C:\Temp -AllowMultiSelect

$Files = @()
$Files += $FileNames


foreach($File in $Files){
    Write-Host "Reading Content for file:" $FIle
    $Content = Get-Content $FIle.FileName
    Write-Host "Content Reading finished!"

    $ReturnObj = @()
    $x = 1;
    foreach ($Line in $Content){
        Write-Host "Processing" $X "of" $Content.Count
        $x++ 
        if(($Line -like "* PACKET *") -and ($line -notlike "*Internal packet identifier*")){
            
            $i = 0
            $Loginfo = $Line.Replace("       "," ").Replace("      "," ").Replace("     "," ").Replace("    "," ").Replace("   "," ").Replace("  "," ").Replace(" ",";").Replace("];","]").split("[").split("]")
            $Date = $Loginfo[0].Split(";")[$i]; $i++
            $Time = $Loginfo[0].Split(";")[$i]; $i++
            $TreadID = $Loginfo[0].Split(";")[$i]; $i++
            $Context = $Loginfo[0].Split(";")[$i]; $i++
            $InternalPacketIdentifier = $Loginfo[0].Split(";")[$i]; $i++
            $TCPUDPIDENTIFIER = $Loginfo[0].Split(";")[$i]; $i++
            $SendReceiveIdentifier = $Loginfo[0].Split(";")[$i]; $i++
            $RemoteIP = $Loginfo[0].Split(";")[$i]; $i++
            $Xid = $Loginfo[0].Split(";")[$i]; $i++
            if ( $Loginfo[0].Split(";")[$i] -eq "R" ){ $QueryOrRespond = "Respond" ; $i++ } else { $QueryRespond = "Query" }
            if ( $Loginfo[0].Split(";")[$i] -eq "Q" ) { $Opcode = "StandardQuery" }
            if ( $Loginfo[0].Split(";")[$i] -eq "N" ) { $Opcode = "Notify" }
            if ( $Loginfo[0].Split(";")[$i] -eq "U" ) { $Opcode = "Update" }
            if ( $Loginfo[0].Split(";")[$i] -eq "?" ) { $Opcode = "Unknown" }
            $FlagsHex = $Loginfo[1].Split(";")[0]
            $FlagsCharCodes = $Loginfo[1].Split(";")[1]
            $Responsecode = $Loginfo[1].Split(";")[2]
            
            $QuestionType =  $Loginfo[2].Split(";")[0]
            $QuestionName =  $Loginfo[2].Split(";")[1].Replace("(0)",".").Replace("(1)",".").Replace("(2)",".").Replace("(3)",".").Replace("(4)",".").Replace("(5)",".").Replace("(6)",".").Replace("(7)",".").Replace("(8)",".").Replace("(9)",".")

            $DateTime = [datetime]::parseexact(($Date + "-" + $Time ), 'dd.MM.yyyy-HH:mm:ss',$null)

            $ReturnObj += [PSCustomObject]@{
            
                 LogTime = $DateTime
                 TreadID = $TreadID
                 Context = $Context
                 InternalPacketIdentifier = $InternalPacketIdentifier
                 TCPUDPIDENTIFIER = $TCPUDPIDENTIFIER
                 SendReceiveIdentifier = $SendReceiveIdentifier
                 RemoteIP = $RemoteIP
                 Xid = $Xid
                 QueryOrRespond = $QueryOrRespond
                 Opcode = $Opcode
                 FlagsHex = $FlagsHex
                 FlagsCharCodes = $FlagsCharCodes
                 Responsecode = $Responsecode
                 QuestionType = $QuestionType
                 QuestionName = $QuestionName

            }


        }


    }


$ReturnObj | Export-Clixml -Path ($FIle.FileName + "Parsed.XML")


}





