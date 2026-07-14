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
- Stateful MFC/EMFC Explicit `Get_Attribute_Single` and `Set_Attribute_Single`
  interpretation for the industry profile objects and attributes used by the supported devices
- Identity and S-Device Supervisor details, including CIP vendor identity and the
  manufacturer/model/revision/serial strings exposed by the device
- Typed values for the DeviceNet Object (`0x03`, instance 1) and Connection Object
  (`0x05`, Explicit instance 1 and Polled I/O instance 2) attributes listed by the
  user-provided device table
- Dynamic `INT`/`REAL` values, engineering-unit attributes, and the supplied device-table
  Sensor attribute `0x6E` configured-full-scale value are interpreted only when the
  required type, unit, and scaling context has been observed
- DeviceNet error, Duplicate MAC ID, Heartbeat, and Shutdown decoding
- Acknowledged Explicit Message fragmentation, acknowledgment, and reassembly
- Group 3 UCMM Open/Close/Error, Heartbeat, and Shutdown decoding
- Stateful UCMM Open correlation that learns dynamic Group 1/2/3 Explicit Connection IDs
- Dynamic Group 2 connections take precedence over the fixed Section 3-7 mapping without
  contaminating the predefined Group 2 state machine
- Selectable Input and Output I/O Assembly decoding for the Volume 1 Section 6-29 Mass Flow
  Controller and Section 6-39 Enhanced Mass Flow Controller profiles
- User-provided device-table Input Assembly 150 (`0x96`,
  Flow/Valve/Temperature/Pressure), Input Assembly 151 (`0x97`, Flow/Valve/Temperature),
  and Output Assembly 152 (`0x98`, Override/Valve), with the documented Counts full-scale
  context; Assembly 150 follows the supplied R02 map
- Assembly component values include their CIP type, device-configured engineering-unit
  context, and mapped object/attribute description
- Unacknowledged DeviceNet I/O fragment reassembly for selected Assembly instances larger
  than eight bytes
- Connected Explicit request/response, fragmentation, object address, and request correlation
  across every learned Message Group
- All CIP common Service Codes from Volume 1 Appendix A, including fixed request/response
  parameter layouts and reserved/object-specific/vendor-specific range classification
- Group 4 Offline Ownership, Identify, Who, and Change MAC ID field decoding and validation
- Raw application data retained alongside optional Assembly decoding for supported I/O profiles
- Manual CAN ID/data entry with an optional millisecond timestamp and derived DLC
- AI structured array import through `zai-rs 0.6.0`, `glm-5-turbo`, and Function Calling
- Compact endpoint selector for Standard URL, Coding Plan URL, or a user-entered Base URL
- API keys remain in memory only
- Plain-text export of only the frames created manually or through AI

The message decoder is checked against DeviceNet Volume 3 Edition 1.16 and the CIP common
service definitions in Volume 1 Edition 3.37. In particular, Volume 3 Section 3-7 identifier
roles and mappings have dedicated regression tests. Explicit decoding follows Volume 3
Sections 2-7.3.1 and 2-7.3.2 for Message Body Formats 0-4, Section 2-7.3.3 for successful
responses, Section 2-7.3.4 for error responses, and Section 2-9 for acknowledged Explicit
fragmentation and reassembly. Because a successful response does not repeat its object path,
typed response interpretation is performed only after correlation with the matching request.
I/O payloads and object/class-specific service tails remain raw when their layouts are not
selected from the supported Volume 1 profiles or defined by the common service specification.

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

When a trace contains I/O-capable messages, the message browser shows Input and Output
Assembly selectors. Host MAC ID defaults to `0`: data produced by the host is decoded with the
selected Output instance, while data produced by another node is decoded with the selected
Input instance. The engineering unit itself is configured in the mapped CIP object and is not
carried in these I/O payloads, so the decoder reports the applicable unit context without
inventing a device-specific scale or unit. Multi-byte `INT` values are signed 16-bit
two's-complement and `REAL` values are IEEE-754 binary32, both little-endian. No implicit
multiplier, divider, base, or offset is applied: converting Counts requires the device's active
Data Units and Full Scale configuration.

The profile uses the first successfully established I/O connection to select the INT or REAL
numeric family. A trace may not contain the connection-establishment order, so mixed Input/Output
selections are decoded independently and reported with a warning instead of suppressing the valid
direction. Status/exception-only instances are neutral.

DeviceNet EDS `[IO_Info]` entries describe a connection's total size, compatibility mask,
display name, and Assembly path; they do not define member boundaries, numeric types, units, or
scaling. An Assembly display name alone therefore remains insufficient evidence for a typed
conversion unless a separate device table defines its members.

All selectable mappings in this analyzer are fixed-size static Assemblies. Their table/EDS total
size is therefore the selected Produced/Consumed Connection Size used to decide whether the
DeviceNet unacknowledged I/O fragmentation protocol is present.

Explicit numeric interpretation is intentionally limited to data used by the Volume 1 Section
6-29 MFC and Section 6-39 EMFC profiles and fields documented by the user-provided device
table/R02 mapping. For the supported Identity, DeviceNet Object, Connection Object, S-Device
Supervisor, S-Analog Sensor, S-Analog Actuator, S-Single Stage Controller, and S-Gas
Calibration attributes, a `Get_Attribute_Single` response is decoded using its correlated
request target. Get requests/responses show a `Read target`; Set requests show a `Write target`
and the parsed value. A `Set_Attribute_Single` request value is displayed immediately, but its new
type/unit/full-scale context is accepted only after the correlated response succeeds. DeviceNet
Object (`0x03`) interpretation covers the documented instance-1 MAC ID, baud-rate, bus-off,
allocation, and hardware-switch values. Connection Object (`0x05`) interpretation covers the
documented Explicit and Polled I/O instances' state, connection IDs and sizes, timing values,
watchdog action, and path lengths/data; unsupported attributes still use the raw-value fallback.

Dynamic values use the object's observed Data Type (`INT` or `REAL`) and a per-instance Data
Units whitelist. If Data Type has not appeared in the trace, an exact two-byte payload is shown
as `INT` and an exact four-byte payload as `REAL` for that field only; the inference is not stored
as device state. Incompatible units, non-finite values, and stale type/unit-dependent scales are
reported and excluded from engineering conversions. When the
supplied device table defines Sensor configured-full-scale attribute `0x6E` (`REAL` amount plus
`UINT` engineering unit) and the required numeric full-scale context is available, Counts can
be converted to the configured engineering value; supported direct physical-unit and
percent-of-full-scale values retain their applicable unit and description. Connection paths are
shown as both raw Packed EPATH bytes and logical targets, and Gas Calibration `DATE` values show
the calendar date plus the encoded day count. Identity results include the standard CIP Vendor
ID and related product identity fields, while Supervisor results expose the manufacturer strings
actually returned by the device. If a request is missing, a response is unsuccessful, a type or
unit is unknown, required scaling context is absent, or an attribute is outside this deliberately
small profile/device-table subset, the analyzer keeps the original attribute/service bytes and
does not guess a conversion.

## Architecture

- `src/lib.rs`: trace parsing and 11-bit DeviceNet identifier model
- `src/analysis.rs`: shared typed decoded-field presentation model
- `src/assembly.rs`: Volume 1 Sections 6-29/6-39 I/O Assembly metadata and component decoder
- `src/explicit.rs`: shared Explicit Message header, body-format, and fragmentation primitives
- `src/path.rs`: shared Packed EPATH logical-segment decoding
- `src/status.rs`: complete CIP General Status metadata from Volume 1 Appendix B
- `src/group2.rs`: stateful predefined Group 2 Only protocol decoder
- `src/protocol.rs`: unified Group 1-4, UCMM, dynamic connection, and Offline Connection Set decoder
- `src/services.rs`: CIP common Service Code metadata and service-data decoder
- `src/mfc_explicit.rs`: profile-scoped MFC/EMFC Explicit attribute metadata, state, and
  numeric/unit interpretation
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
frame numbers repeat. Use `decode_trace_ordered_with_io` with an
`IoAssemblySelection` to apply the Section 6-29/6-39 Assembly mapping and I/O
fragment reassembly.

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
