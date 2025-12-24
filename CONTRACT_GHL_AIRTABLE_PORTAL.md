# ContentBug Data Contract: GHL ↔ Airtable ↔ Portal

**Version**: 1.0.0
**Last Updated**: 2024-12-24

## Source of Truth Hierarchy

| Domain | Source of Truth | Syncs To |
|--------|-----------------|----------|
| **Billing/Payments** | GHL (GoHighLevel) | Airtable via webhook |
| **Plan/Subscription** | GHL | Airtable `Contacts.Plan`, `Entitlement Status` |
| **Client Identity** | GHL | Airtable `Contacts` table |
| **Operational Work** | Airtable | Portal displays |
| **Projects** | Airtable | Portal, Editor tools |
| **Blueprints** | Airtable | Portal, Project creation |
| **Assignments** | Airtable | Portal |
| **Chat/Messages** | Airtable | Portal real-time |
| **Sessions/Auth** | Airtable | Portal cookies |

---

## GHL → Airtable Sync (via Make.com or Webhooks)

### Trigger Events from GHL

| GHL Event | Airtable Action | Target Table |
|-----------|-----------------|--------------|
| Contact Created | Create record | Contacts |
| Contact Updated | Update record | Contacts |
| Payment Success | Create record + Update Plan | Transactions, Contacts |
| Subscription Changed | Update Plan + Entitlement | Contacts |
| Trial Started | Set Plan='Free Trial', TrialStartDate | Contacts |
| Cancellation | Set Entitlement='canceled' | Contacts |

### Field Mappings: GHL Contact → Airtable Contacts

| GHL Field | Airtable Field | Type | Notes |
|-----------|----------------|------|-------|
| `id` | `GHLID` | string | GHL contact ID |
| `email` | `Email` | email | Primary identifier |
| `firstName` | `First Name` | string | |
| `lastName` | `Last Name` | string | |
| `phone` | `Phone` | phone | |
| `tags[]` | `Plan` | singleSelect | Map tag to plan name |
| `customFields.subscription_status` | `Entitlement Status` | singleSelect | active/trial/past_due/canceled |

### Example GHL Webhook Payload

```json
{
  "type": "contact.updated",
  "contact": {
    "id": "abc123",
    "email": "client@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "phone": "+15551234567",
    "tags": ["Pro Plan", "Active"],
    "customFields": {
      "subscription_status": "active",
      "subscription_plan": "Pro"
    }
  }
}
```

---

## Airtable Schema Reference

### Contacts Table

| Field | Type | Description | Source |
|-------|------|-------------|--------|
| `Email` | email | Primary identifier | GHL |
| `Contact Name` | string | Full name | GHL |
| `First Name` | string | | GHL |
| `Phone` | phone | | GHL |
| `Plan` | singleSelect | Free Trial, Starter, Growth, Creator, Pro | GHL |
| `Entitlement Status` | singleSelect | trial, active, past_due, locked, canceled | GHL |
| `EditorAssignedId` | string | Team record ID of assigned editor | Portal |
| `EditorAssignedEmail` | string | Editor's email | Portal |
| `EditorAssignedName` | string | Editor's name | Portal |
| `OnboardingStep` | singleSelect | step-1, step-2, step-3, complete | Portal |
| `LastActiveAt` | dateTime | Last portal activity | Portal |
| `ChatChannelID` | string | Auto-created channel ID | Portal |
| `DriveFolderID` | string | Google Drive folder ID | Portal |
| `isSample` | checkbox | True if demo/test data | Portal |

### Projects Table

| Field | Type | Description | Source |
|-------|------|-------------|--------|
| `Project UUID` | string | URL-safe unique ID | Portal |
| `Project Name` | string | Title | Portal |
| `Status` | singleSelect | queued, in_edit, review_ready, revisions, approved, delivered, archived | Portal |
| `Client` | linkedRecord → Contacts | | Portal |
| `ClientEmail` | string | Denormalized for filtering | Portal |
| `ClientName` | string | Denormalized | Portal |
| `AssignedEditorId` | string | Team record ID | Portal |
| `AssignedEditorName` | string | Denormalized | Portal |
| `Project Format` | singleSelect | short, long | Portal |
| `Project Tier` | singleSelect | tier_1, tier_2, tier_3 | Portal |
| `Blueprint` | linkedRecord → Style-Blueprints | | Portal |
| `Blueprint Name` | string | Denormalized | Portal |
| `ETA` | dateTime | Client-facing estimate | Portal |
| `Editor Due Date` | dateTime | Internal deadline | Portal |
| `Expected Due Date` | dateTime | Latest acceptable date | Portal |
| `Revision Round Count` | number | Times sent back | Portal |
| `Revision History` | longText | JSON array of revisions | Portal |
| `QualityScore` | number | 1-10 client rating | Portal |
| `ThumbnailURL` | url | Project thumbnail | Portal |
| `CreatedAt` | dateTime | Submission timestamp | Portal |
| `isSample` | checkbox | True if demo data | Portal |

### Team Table

| Field | Type | Description |
|-------|------|-------------|
| `Name` | string | Full name |
| `Email` | email | Login identifier |
| `Role` | singleSelect | editor, admin, owner |
| `Active` | checkbox | Currently active |
| `AvatarURL` | url | Profile image |
| `ActiveProjectCount` | number | Computed |
| `ActiveClients` | number | Computed |
| `AvgQualityScore` | number | Average across projects |
| `AvgTurnaroundScore` | number | Average delivery speed |
| `LateProjectCount` | number | Currently overdue |
| `CurrentPayout` | number | Pending payout (cents) |

### Chat-Channels Table

| Field | Type | Description |
|-------|------|-------------|
| `ChannelID` | string | Unique channel identifier |
| `Name` | string | Display name |
| `Type` | singleSelect | project, support, team, private |
| `Client` | linkedRecord → Contacts | |
| `Project` | linkedRecord → Projects | |
| `Participants` | string | Comma-separated emails |
| `LastMessageAt` | dateTime | |
| `UnreadCount` | number | |
| `isSample` | checkbox | |

### Chat-Messages Table

| Field | Type | Description |
|-------|------|-------------|
| `ChannelID` | string | Parent channel |
| `SenderID` | string | Email or 'system' |
| `SenderName` | string | Display name |
| `SenderRole` | singleSelect | client, editor, admin, system |
| `Content` | longText | Message text |
| `Type` | singleSelect | text, system, attachment |
| `CreatedAt` | dateTime | |
| `IsRead` | checkbox | |
| `isSample` | checkbox | |

---

## Portal Permission Model

### Role Hierarchy

```
owner > admin > editor > client
```

### Access Matrix

| Resource | client | editor | admin | owner |
|----------|--------|--------|-------|-------|
| Own projects | R | - | - | - |
| Assigned projects | - | RW | RW | RW |
| All projects | - | - | RW | RW |
| Own clients | - | R | - | - |
| All clients | - | - | RW | RW |
| Team members | - | R | RW | RW |
| Assignment board | - | - | RW | RW |
| Purge sample data | - | - | - | W |
| Revenue metrics | - | - | R | RW |

R = Read, W = Write, RW = Read+Write

---

## Status Transitions

### Project Status Flow

```
draft → queued → in_edit → review_ready → approved → delivered
                    ↑            ↓
                    ←── revisions ←
```

### Who Can Transition

| From | To | Who Can Do It |
|------|-----|---------------|
| queued | in_edit | editor (assigned), admin, owner |
| in_edit | review_ready | editor (assigned), admin, owner |
| review_ready | revisions | client (own project), admin, owner |
| revisions | review_ready | editor (assigned), admin, owner |
| review_ready | approved | client (own project), admin, owner |
| approved | delivered | admin, owner |

---

## Failure Behavior

### API Offline
- Portal shows cached data where available
- Write operations queue in localStorage
- User sees "Offline mode" banner
- Sync attempts every 30 seconds

### Missing Data
- Projects with no blueprint: Show "No Blueprint" chip
- Projects with no editor: Show "Unassigned" in card
- Contacts with no plan: Default to "Free Trial"
- Missing thumbnails: Show placeholder gradient

### Authentication Failure
- Session expired: Redirect to /login
- Rate limited: Show retry timer
- Invalid OTP: Increment attempt counter, lock after 5

---

## Versioning

- API version in healthz response: `production-X.Y.Z`
- Contract version in this document header
- Breaking changes require major version bump
- Notify all integrations (Make, GHL webhooks) before breaking changes
