# Build the delivery image. Context is the deliver/ directory.
#   .\build-image.ps1                 -> im-arvo:2018-01-16
#   .\build-image.ps1 -Tag im-arvo:test
param([string]$Tag = 'im-arvo:2018-01-16')
$ErrorActionPreference = 'Stop'
$deliver = Split-Path $PSScriptRoot -Parent
& docker build -f (Join-Path $PSScriptRoot 'Dockerfile') -t $Tag $deliver
exit $LASTEXITCODE
