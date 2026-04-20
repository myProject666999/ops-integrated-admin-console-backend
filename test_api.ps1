# API测试脚本
$baseUrl = "http://127.0.0.1:8080"

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Testing OPS Admin Backend API" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# 1. Test health endpoint
Write-Host "`n[1] Testing health endpoint..." -ForegroundColor Yellow
$healthResponse = Invoke-RestMethod -Uri "$baseUrl/health" -Method GET
Write-Host "Health check response: $($healthResponse | ConvertTo-Json)" -ForegroundColor Green

# 2. Register user (if not exists)
Write-Host "`n[2] Registering test user..." -ForegroundColor Yellow
$registerBody = @{
    username = "testadmin"
    password = "TestPass123!"
} | ConvertTo-Json

try {
    $registerResponse = Invoke-RestMethod -Uri "$baseUrl/api/auth/register" -Method POST -Body $registerBody -ContentType "application/json"
    Write-Host "Register response: $($registerResponse | ConvertTo-Json)" -ForegroundColor Green
} catch {
    Write-Host "Register failed (user may exist): $($_.Exception.Message)" -ForegroundColor Yellow
}

# 3. Login to get token
Write-Host "`n[3] Login to get Token..." -ForegroundColor Yellow
$loginBody = @{
    username = "testadmin"
    password = "TestPass123!"
} | ConvertTo-Json

$loginResponse = Invoke-RestMethod -Uri "$baseUrl/api/auth/login" -Method POST -Body $loginBody -ContentType "application/json"
Write-Host "Login response: $($loginResponse | ConvertTo-Json)" -ForegroundColor Green

$token = $loginResponse.token
Write-Host "Got Token: $token" -ForegroundColor Cyan

# 4. Test /api/admins endpoint
Write-Host "`n[4] Testing /api/admins endpoint..." -ForegroundColor Yellow
$headers = @{
    "Authorization" = "Bearer $token"
}

$adminsResponse = Invoke-RestMethod -Uri "$baseUrl/api/admins" -Method GET -Headers $headers
Write-Host "Admins API response:" -ForegroundColor Green
$adminsResponse | ConvertTo-Json -Depth 3

# 5. Verify response fields
Write-Host "`n[5] Verifying response fields..." -ForegroundColor Yellow
if ($adminsResponse.items) {
    foreach ($admin in $adminsResponse.items) {
        Write-Host "Admin record: id=$($admin.id), username=$($admin.username), updated_at=$($admin.updated_at)" -ForegroundColor Green

        # Check fields exist
        if ($admin.id -eq $null) {
            Write-Host "ERROR: Missing id field!" -ForegroundColor Red
        }
        if ($admin.username -eq $null) {
            Write-Host "ERROR: Missing username field!" -ForegroundColor Red
        }
        if ($admin.updated_at -eq $null) {
            Write-Host "ERROR: Missing updated_at field!" -ForegroundColor Red
        }
    }
    Write-Host "`nAll fields verified! Total $($adminsResponse.items.Count) records" -ForegroundColor Green
} else {
    Write-Host "ERROR: No items field in response!" -ForegroundColor Red
}

# 6. Test unauthorized access
Write-Host "`n[6] Testing unauthorized access..." -ForegroundColor Yellow
try {
    $unauthorizedResponse = Invoke-RestMethod -Uri "$baseUrl/api/admins" -Method GET
    Write-Host "ERROR: Unauthorized access should be rejected!" -ForegroundColor Red
} catch {
    if ($_.Exception.Response.StatusCode -eq 401) {
        Write-Host "OK: Unauthorized access returns 401" -ForegroundColor Green
    } else {
        Write-Host "ERROR: Unauthorized access returned non-401 status: $($_.Exception.Response.StatusCode)" -ForegroundColor Red
    }
}

# 7. Test invalid token
Write-Host "`n[7] Testing invalid Token..." -ForegroundColor Yellow
try {
    $invalidHeaders = @{
        "Authorization" = "Bearer invalid-token"
    }
    $invalidResponse = Invoke-RestMethod -Uri "$baseUrl/api/admins" -Method GET -Headers $invalidHeaders
    Write-Host "ERROR: Invalid token should be rejected!" -ForegroundColor Red
} catch {
    if ($_.Exception.Response.StatusCode -eq 401) {
        Write-Host "OK: Invalid Token returns 401" -ForegroundColor Green
    } else {
        Write-Host "ERROR: Invalid Token returned non-401 status: $($_.Exception.Response.StatusCode)" -ForegroundColor Red
    }
}

Write-Host "`n=========================================" -ForegroundColor Cyan
Write-Host "All tests completed!" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
