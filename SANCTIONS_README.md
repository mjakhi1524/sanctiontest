# Local Sanctions System for Relay API

## Overview

The Relay API now uses a **local sanctions checking system** instead of querying Supabase for every transaction. This provides:

- ⚡ **Faster performance** - No database queries for sanctions checks
- 🔒 **Better reliability** - Works even if Supabase is down
- 📝 **Easy management** - Update sanctions list via API or file editing
- 🚀 **Deployment ready** - Works seamlessly on Render

## How It Works

### 1. File-Based Storage
- Sanctions list is stored in `sanctioned_wallets.json`
- Automatically loaded when the API starts
- File is watched for changes and reloaded automatically

### 2. Automatic Detection
- Every transaction to `/v1/relay` is checked against the sanctions list
- If the "to" address is sanctioned, the transaction is **BLOCKED**
- Clear logging shows when sanctions are detected

### 3. Risk Score Fix
- Fixed the issue where risk scores were always returning 21
- Now properly calculates risk based on transaction context
- Provides meaningful risk assessment even without custom features

## File Structure

```
relay-api/
├── app/
│   ├── main.py                 # Main API with sanctions integration
│   ├── local_sanctions.py      # Local sanctions checker
│   └── ...
├── sanctioned_wallets.json     # Sanctions list (update manually)
└── test_local_sanctions.py     # Test script
```

## Sanctions List Format

```json
{
  "sanctioned_addresses": [
    "0x4f47bc496083c727c5fbe3ce9cdf2b0f6496270c",
    "0x983a81ca6FB1e441266D2FbcB7D8E530AC2E05A2",
    "0xb6f5ec1a0a9cd1526536d3f0426c429529471f40"
  ],
  "last_updated": "2025-01-20T00:00:00Z",
  "description": "Local sanctioned wallets list - update manually as needed",
  "total_count": 3
}
```

## API Endpoints

### 1. Check Sanctions Status
```bash
GET /v1/sanctions/check/{address}
```
**Example:**
```bash
curl -X GET "https://your-api.onrender.com/v1/sanctions/check/0x4f47bc496083c727c5fbe3ce9cdf2b0f6496270c" \
  -H "Authorization: Bearer YOUR_API_KEY"
```

**Response:**
```json
{
  "address": "0x4f47bc496083c727c5fbe3ce9cdf2b0f6496270c",
  "is_sanctioned": true,
  "status": "SANCTIONED",
  "message": "Address 0x4f47bc496083c727c5fbe3ce9cdf2b0f6496270c is SANCTIONED",
  "checked_at": "2025-01-20T10:30:00Z"
}
```

### 2. Get Sanctions List
```bash
GET /v1/sanctions/list
```
**Response:**
```json
{
  "success": true,
  "total_count": 3,
  "addresses": [
    "0x4f47bc496083c727c5fbe3ce9cdf2b0f6496270c",
    "0x983a81ca6FB1e441266D2FbcB7D8E530AC2E05A2",
    "0xb6f5ec1a0a9cd1526536d3f0426c429529471f40"
  ],
  "last_updated": "2025-01-20T00:00:00Z",
  "description": "Local sanctioned wallets list"
}
```

### 3. Manage Sanctions List
```bash
POST /v1/sanctions/manage
```

**Add Address:**
```json
{
  "address": "0x9999999999999999999999999999999999999999",
  "action": "add"
}
```

**Remove Address:**
```json
{
  "address": "0x9999999999999999999999999999999999999999",
  "action": "remove"
}
```

### 4. Get Sanctions Statistics
```bash
GET /v1/sanctions/stats
```

## How to Update Sanctions List

### Method 1: API Management (Recommended)
Use the `/v1/sanctions/manage` endpoint to add/remove addresses programmatically.

### Method 2: File Editing
1. Edit `sanctioned_wallets.json` locally
2. Redeploy to Render
3. The API will automatically reload the new list

### Method 3: Direct File Upload
1. Upload a new `sanctioned_wallets.json` to Render
2. Restart the service
3. The API will load the new list

## Testing

### Run Local Test
```bash
cd relay-api
python test_local_sanctions.py
```

### Test with Real API
```bash
# Test sanctions check
curl -X GET "https://your-api.onrender.com/v1/sanctions/check/0x4f47bc496083c727c5fbe3ce9cdf2b0f6496270c" \
  -H "Authorization: Bearer YOUR_API_KEY"

# Test relay with sanctioned address
curl -X POST "https://your-api.onrender.com/v1/relay" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "chain": "ethereum",
    "rawTx": "YOUR_RAW_TX_TO_SANCTIONED_ADDRESS"
  }'
```

## Deployment on Render

### 1. File Structure
Ensure your Render deployment includes:
- `relay-api/app/main.py`
- `relay-api/app/local_sanctions.py`
- `relay-api/sanctioned_wallets.json`

### 2. Environment Variables
No additional environment variables needed for sanctions checking.

### 3. File Permissions
The API will automatically create the sanctions file if it doesn't exist.

## Security Features

- ✅ **Address Validation** - Ensures valid 0x-prefixed addresses
- ✅ **Case Insensitive** - Normalizes addresses for consistent checking
- ✅ **File Watching** - Automatically reloads when file changes
- ✅ **Error Handling** - Graceful fallback if file is corrupted
- ✅ **API Key Protection** - All endpoints require valid API key

## Monitoring and Logging

### Console Logs
The API provides clear logging:
```
🚫 SANCTIONED WALLET DETECTED in relay: 0x4f47bc496083c727c5fbe3ce9cdf2b0f6496270c
   Transaction will be BLOCKED from broadcasting
```

### API Responses
- **403 Forbidden** - Transaction blocked due to sanctions
- **200 OK** - Transaction allowed (clean address)
- **400 Bad Request** - Invalid address format

## Troubleshooting

### Issue: Sanctions not being detected
1. Check if `sanctioned_wallets.json` exists
2. Verify file format is valid JSON
3. Check API logs for file loading errors

### Issue: File not updating
1. Ensure file has correct permissions
2. Check file path in logs
3. Restart the service if needed

### Issue: API errors
1. Check API key authentication
2. Verify address format (0x-prefixed, 42 characters)
3. Check service logs for detailed errors

## Performance Benefits

- **Before**: Database query for every transaction
- **After**: In-memory lookup for sanctions
- **Improvement**: ~10-100x faster sanctions checking
- **Reliability**: Works offline, no database dependency

## Future Enhancements

- [ ] Bulk import/export of sanctions list
- [ ] Webhook notifications for sanctions detection
- [ ] Integration with external sanctions APIs
- [ ] Advanced pattern matching for addresses
- [ ] Audit trail for sanctions list changes

---

## Quick Start

1. **Deploy** your API to Render
2. **Test** with a known sanctioned address
3. **Verify** the transaction is blocked
4. **Update** the sanctions list as needed via API
5. **Monitor** logs for sanctions detection

The system is now fully self-contained and will work reliably on Render without any external database dependencies for sanctions checking!


