# DeviceNet Trace Analyzer

A Windows/Linux desktop utility built with `egui/eframe 0.35`. It opens
PCAN-Explorer trace logs, extracts and time-sorts every recognizable CAN
message, and decodes the selected DeviceNet frame across Message Groups 1-4.

## Features

- Group 1: `0x000-0x3FF`; all identifier fields plus the fixed Predefined
  Controller/Device Connection Set functions for Message IDs `0xC-0xF`
- Group 2: `0x400-0x5FF`; all eight predefined Group 2 Only functions
- Group 3: `0x600-0x7BF`; connection-specific IDs 0-4, UCMM response/request IDs 5/6,
  and invalid ID 7 validation
- Group 4: `0x7C0-0x7EF`; reserved IDs plus all Offline Connection Set request and
  response formats (`0x2C-0x2F`)
- Invalid identifiers: `0x7F0-0x7FF`
- PCAN-Explorer `.log` / `.trc` file picker and drag-and-drop loading
- Virtualized, time-ordered message selection list for large traces
- Search plus Group 1/2/3/4, Explicit, and direction filters with per-group statistics
- Resizable message browser, keyboard navigation, and raw-data copy action
- Complete Group 2 Message ID 0-7 function classification
- Group 2 Only Allocate/Release request and response decoding
- Stateful Message Body Format 0-4 tracking and object address decoding
- Generic connected Explicit Request/Response service decoding and correlation
- DeviceNet error, Duplicate MAC ID, Heartbeat, and Shutdown decoding
- Acknowledged Explicit Message fragmentation, acknowledgment, and reassembly
- Group 3 UCMM Open/Close/Error, Heartbeat, and Shutdown decoding
- Stateful UCMM Open correlation that learns dynamic Group 1/2/3 Explicit Connection IDs
- Dynamic Group 2 connections take precedence over the fixed Section 3-7 mapping without
  contaminating the predefined Group 2 state machine
- Connected Explicit request/response, fragmentation, object address, and request correlation
  across every learned Message Group
- All CIP common Service Codes from Volume 1 Appendix A, including fixed request/response
  parameter layouts and reserved/object-specific/vendor-specific range classification
- Group 4 Offline Ownership, Identify, Who, and Change MAC ID field decoding and validation
- Raw application data for Bit-Strobe, Multicast Poll, COS/Cyclic, and Poll I/O
- Manual CAN ID/data entry with an optional millisecond timestamp and derived DLC
- AI structured array import through `zai-rs 0.6.0`, `glm-5-turbo`, and Function Calling
- Compact endpoint selector for Standard URL, Coding Plan URL, or a user-entered Base URL
- API keys remain in memory only
- Plain-text export of only the frames created manually or through AI

The message decoder is checked against DeviceNet Volume 3 Edition 1.16 and the CIP common
service definitions in Volume 1 Edition 3.37. In particular, Volume 3 Section 3-7 identifier
roles and mappings have dedicated regression tests. I/O payloads and object/class-specific
service tails remain raw when their layouts are not defined by the identifier mapping or common
service specification.

## Run

```powershell
cargo run --release
```

An optional trace path may be supplied on the command line:

```powershell
cargo run --release -- D:\pcan\Trace4.log
```

Trace files can also be opened from the toolbar or dropped anywhere on the
application window. Click a time-ordered message row to update the analysis
panel. Use the time-order button to switch between ascending and descending
order. The original parsed order and stateful decoder results are retained;
sorting changes presentation only.

Use **Add messages** for manual or AI-assisted entry. A blank manual timestamp is
stored as missing and remains after all timestamped frames in both sort modes;
multiple missing timestamps retain insertion order. AI entry accepts prose,
key/value records, or multiple pasted frames. The strict extraction prompt keeps
missing time as `null`, normalizes identifiers and hexadecimal bytes to JSON
integers, validates DLC against the byte count, and never invents missing frame
content. The AI input editor has a fixed viewport with internal scrolling, and
the complete entry window scrolls on smaller displays.

## Architecture

- `src/lib.rs`: trace parsing and 11-bit DeviceNet identifier model
- `src/analysis.rs`: shared typed decoded-field presentation model
- `src/explicit.rs`: shared Explicit Message header, body-format, and fragmentation primitives
- `src/path.rs`: shared Packed EPATH logical-segment decoding
- `src/status.rs`: complete CIP General Status metadata from Volume 1 Appendix B
- `src/group2.rs`: stateful predefined Group 2 Only protocol decoder
- `src/protocol.rs`: unified Group 1-4, UCMM, dynamic connection, and Offline Connection Set decoder
- `src/services.rs`: CIP common Service Code metadata and service-data decoder
- `src/app.rs`: document, selection, sort, filter, and derived-statistics state
- `src/frame_input.rs`: manual frame validation, source tracking, and text export
- `src/ai_import.rs`: optimized extraction prompt and Z.ai Function Calling client
- `src/ui.rs`: egui presentation and interaction layer
- `src/theme.rs`: shared color, typography, spacing, and widget styling

The UI addresses messages by their stable source index instead of the display
message number. Duplicate frame numbers therefore cannot overwrite decoder
results or collide with UI state. Each source frame, analysis, and origin is held
in one `AnalyzedFrame`, eliminating parallel-vector indexing invariants.

Use the unified `decode_trace_ordered` library API when UCMM-allocated Group 2
connections may be present. The standalone Group 2 decoder intentionally has no
UCMM connection context, and map-based compatibility APIs are lossy when display
frame numbers repeat.

## Supported single-frame input formats

```text
123
0x400
0b11010101010
d:1024
123#11 22 33
can0 7EF#AABB
Bus=1,ID=1038,Type=D,DLC=6,Data=0 75 3 1 1 0 ,
```

Unprefixed standalone identifiers use hexadecimal. The `ID=` field in a
comma-separated key/value record uses decimal (or an explicit `0x` prefix).

## Test

```powershell
cargo test
```
