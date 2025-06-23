param (
  [string]$path,
  [string]$action  # "lock" or "unlock"
)

if ($action -eq "lock") {
  icacls $path /inheritance:r           # Remove inherited permissions
  icacls $path /deny "$env:USERNAME:(R,W)"  # Deny Read and Write to current user
}
elseif ($action -eq "unlock") {
  icacls $path /remove:d "$env:USERNAME"   # Remove deny rule
  icacls $path /grant "$env:USERNAME:(R,W)"  # Grant back Read and Write
  icacls $path /inheritance:e              # Re-enable inheritance
}