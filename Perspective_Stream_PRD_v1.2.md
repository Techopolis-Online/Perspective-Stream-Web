# Product Requirements Document (PRD)

## Perspective Stream — Version 1.0

---

### Document Information

- **Product Name**: Perspective Stream  
- **Version**: 1.0  
- **Document Version**: 1.2  
- **Last Updated**: August 8, 2025  
- **Author**: Techopolis Online Solutions – Accessibility & AI Team  
- **Status**: Draft for Review  

---

## 1. Executive Summary

### 1.1 Product Overview

Perspective Stream is a live broadcasting platform for all creators to stream simultaneously to internet radio stations and YouTube, with complete in-platform control of streaming, broadcast management, and audience engagement.  
It integrates YouTube OAuth for scheduling, starting, stopping, and configuring broadcasts (including **public, unlisted, and private**), handles radio streaming, and provides accessibility-first overlays, monetization alerts, and **custom event sound triggers** such as “Breaking News” cues.

### 1.2 Vision Statement

To deliver a one-stop live streaming control hub for creators of all sizes — accessible, flexible, and powerful enough to handle every stage of a broadcast without requiring third-party tools.

### 1.3 Key Value Propositions

- **Dual-destination streaming**: Go live on radio and YouTube at the same time.  
- **Full broadcast control**: Privacy changes, metadata edits, overlay control, and stream state from one dashboard.  
- **Priority alerts**: Super Chats and memberships trigger instant sound + TTS.  
- **Event sound triggers**: Play “Breaking News” or other pre-set sound cues instantly.  
- **Scheduling + privacy**: Plan broadcasts in advance with the chosen privacy level.  
- **Accessibility-first**: WCAG-compliant interface with keyboard and screen reader support.  

---

## 2. Product Scope

### 2.1 In Scope (Version 1.0)

- **Authentication & YouTube OAuth**  
  - Django-based login.  
  - YouTube OAuth connection with token storage and refresh.

- **Destinations**  
  - Multiple radio stations (Icecast/Shoutcast) per account.  
  - YouTube RTMP via OAuth-bound stream keys.

- **Broadcast Scheduling**  
  - Create, edit, delete scheduled YouTube broadcasts with:  
    - Title, description, category, tags.  
    - Start date/time (UTC/local).  
    - Privacy: **public**, **unlisted**, **private**.  
  - Assign stations to broadcasts.  
  - Auto-transition testing → live at start time.

- **Live Control**  
  - Start/stop radio and YouTube streams.  
  - Change privacy level during live broadcast.  
  - Update title/description/tags while live.  
  - Manage chat (pin/remove/block).  
  - Activate overlays and BRB scenes mid-stream.

- **Alerts & TTS**  
  - Poll YouTube live chat for messages, Super Chats, memberships.  
  - Priority queue: monetization events first with sound + TTS.  
  - Configurable TTS output (monitor-only or program feed).  
  - Rate limiting and word filtering.

- **Event Sound Triggers**  
  - Pre-configured audio cues for scenarios like:  
    - Breaking News.  
    - Technical Difficulties.  
    - Commercial Break.  
    - Custom uploaded sounds.  
  - Play instantly via hotkey or control panel button.  
  - Optional overlay animation linked to sound.

- **Overlays**  
  - BRB/On Break screen with editable text and countdown.  
  - Lower-thirds and logo bug.  
  - Alert animations for monetization and custom events.

- **Test Mode**  
  - Stream to unlisted YouTube “testing” broadcasts.  
  - Push to radio test mount.  
  - Inject fake events to test alerts and overlays.

- **REST API**  
  - Endpoints for all broadcast, stream, overlay, alert, and event sound controls.  
  - WebSocket for chat, alerts, and status.

- **Accessibility**  
  - All actions available via keyboard shortcuts.  
  - Screen reader-optimized interface with ARIA live regions.  

### 2.2 Out of Scope (Version 1.0)

- Multi-user conferencing/video guest routing.  
- Native mobile apps (future).  
- Server-side video recording/VOD hosting.

---

## 3. Target Users

- **Content creators**: YouTubers, podcasters, event streamers.  
- **Radio hosts**: Those wanting to simulcast to YouTube.  
- **News broadcasters**: Needing instant “Breaking News” sound cues.  
- **Accessibility-conscious streamers**: Anyone needing keyboard-only workflows.

---

## 4. Functional Requirements

### 4.1 Account & Auth
- Sign up/login with password.  
- Connect/disconnect YouTube via OAuth.  
- API tokens for external integration.

### 4.2 Destination Management
- Add/edit/remove stations.  
- Test connection.  
- Enable/disable per broadcast.

### 4.3 Scheduling
- Create/edit/delete YouTube broadcasts with all metadata.  
- Choose privacy level (**public**, **unlisted**, **private**).  
- Auto-start pipelines at scheduled time.

### 4.4 Streaming Control
- Start/stop all destinations together or individually.  
- Change YouTube broadcast privacy mid-stream.  
- Edit broadcast metadata while live.  
- Apply overlays without stopping stream.

### 4.5 Chat, Alerts & TTS
- Poll for events.  
- Priority queue for monetization events.  
- Sound + TTS for Super Chats/memberships.  
- Display animations in overlays.

### 4.6 Event Sound Triggers
- Configure predefined sounds (“Breaking News”, “Technical Difficulties”, etc.).  
- Upload custom sounds.  
- Map sounds to hotkeys.  
- Optional matching overlay animation.

### 4.7 Overlays
- BRB screen with live activation.  
- Custom lower-thirds.  
- Alert overlays for events.

### 4.8 Test Mode
- Unlisted YouTube broadcast in “testing” state.  
- Radio test mount.  
- Simulate events for QA.

### 4.9 REST API
- Full CRUD and control endpoints for broadcasts, destinations, overlays, alerts, and event sounds.  
- WebSocket for real-time updates.

---

## 5. Non-Functional Requirements

- **Performance**: Event-to-alert or sound trigger latency < 3 seconds.  
- **Reliability**: Auto-reconnect FFmpeg pipelines.  
- **Security**: Encrypted token storage, HTTPS, secure cookies.  
- **Scalability**: Handle concurrent streams.  
- **Accessibility**: WCAG 2.2 AA.

---

## 6. UI Requirements

- **Dashboard**: Upcoming broadcasts, go-live button, destination health.  
- **Broadcast Editor**: All metadata + privacy controls.  
- **Live Room**: Stream controls, privacy switcher, overlays, chat, alerts, and event sound trigger panel.  
- **Stations Manager**: Configure and test radio stations.  
- **Settings**: OAuth, TTS settings, hotkeys, sound library.

---

## 7. Technical Architecture

### 7.1 Django Apps
- `accounts` — auth, tokens.  
- `youtube_integration` — OAuth, API calls.  
- `stations` — radio config.  
- `broadcasts` — metadata & scheduling.  
- `streams` — FFmpeg orchestration.  
- `chat` — polling & event processing.  
- `alerts` — configuration & delivery.  
- `event_sounds` — sound library, hotkey mapping, playback.  
- `overlays` — web-based scenes.  
- `api` — DRF endpoints.  

### 7.2 Core Components
- Django + DRF + Channels.  
- Celery + Redis for tasks.  
- FFmpeg for media routing.  
- Firebase (for now) as primary data store.  
- Prometheus + Grafana metrics.

---

## 8. Quality Assurance

- Unit tests for auth, broadcast creation, streaming control, chat parsing.  
- Integration tests for go-live workflows.  
- Accessibility tests with screen readers.  
- Event sound trigger tests for latency and reliability.

---

## 9. Release Plan

### Milestone 1 — Core Streaming
- OAuth, station config, manual start/stop.

### Milestone 2 — Scheduling & Alerts
- Full scheduling, chat polling, priority alerts with TTS.

### Milestone 3 — Overlays & Event Sounds
- BRB overlays, privacy changes during live, event sound triggers, test stream workflows.

---

## 10. Success Metrics

- ≥ 95% success rate for broadcast start without manual fixes.  
- Median alert/sound trigger latency ≤ 3 seconds.  
- ≥ 90% positive feedback from accessibility testing.

---

## 11. Conclusion

Perspective Stream v1.0 will allow creators to manage **all** broadcast controls — including private streams, privacy changes, overlays, monetization alerts, and instant event sounds like “Breaking News” — from a single accessible interface. It will be a complete control hub for live production across YouTube and radio.
