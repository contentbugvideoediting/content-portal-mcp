# GHL Workflow Setup: Demo Booking → Trial Start

## Option 1: Direct GHL Workflow (Recommended)

### Step 1: Create New Workflow
1. Go to **Automation** → **Workflows** in GHL
2. Click **+ Create Workflow**
3. Name it: `Portal - Demo Booked → Start Trial`

### Step 2: Add Trigger
1. Click **Add New Trigger**
2. Select **Appointment Status**
3. Configure:
   - **Appointment Status**: `Booked`
   - **In Calendar**: Select your Demo Call calendar
   - Click **Save Trigger**

### Step 3: Add Webhook Action
1. Click **+** to add action
2. Search for **Webhook**
3. Select **Custom Webhook**
4. Configure:
   - **Method**: `POST`
   - **URL**: `https://portalv2.contentbug.io/api/webhook/ghl/demo-booked`
   - **Headers**: 
     ```
     Content-Type: application/json
     ```
   - **Body** (JSON):
     ```json
     {
       "contact": {
         "email": "{{contact.email}}",
         "firstName": "{{contact.first_name}}",
         "lastName": "{{contact.last_name}}",
         "phone": "{{contact.phone}}"
       },
       "appointment": {
         "id": "{{appointment.id}}",
         "calendar_id": "{{appointment.calendar_id}}",
         "start_time": "{{appointment.start_time}}"
       }
     }
     ```

### Step 4: Publish
1. Click **Save**
2. Toggle workflow to **Published**

---

## Option 2: Using Zapier (Alternative)

### Zap Configuration
**Trigger**: GoHighLevel → New Appointment Booked
**Action**: Webhooks by Zapier → POST

**POST URL**: `https://portalv2.contentbug.io/api/webhook/ghl/demo-booked`

**Body**:
```json
{
  "contact": {
    "email": "<Email from GHL>",
    "firstName": "<First Name from GHL>",
    "lastName": "<Last Name from GHL>",
    "phone": "<Phone from GHL>"
  }
}
```

---

## What Happens When Webhook Fires

1. ✅ Contact found/created in GHL
2. ✅ Google Drive folder created: `[Name] - Content Bug`
3. ✅ Subfolders created: Raw Sessions, Completed Edits, Brand Assets
4. ✅ GHL contact updated with:
   - `googleDriveFolderLink` = folder URL
   - `subscriptionStatus` = Trial
   - `onboardingStatus` = Demo Booked
5. ✅ Tags added: `free-trial`, `demo-booked`, `drive-folder-created`

---

## Testing

Test the webhook manually:
```bash
curl -X POST https://portalv2.contentbug.io/api/webhook/ghl/demo-booked \
  -H "Content-Type: application/json" \
  -d '{"contact":{"email":"test@example.com","firstName":"Test","lastName":"User"}}'
```

Expected response:
```json
{
  "received": true,
  "email": "test@example.com", 
  "trial_started": true,
  "drive_folder": true
}
```
