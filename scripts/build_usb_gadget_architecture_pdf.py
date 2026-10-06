#!/usr/bin/env python3
"""Build the offline USB gadget architecture guide.

The checked-in Markdown guide is the detailed browser-readable source. This
script produces a compact, visually structured companion PDF from the same
current version-1 architecture.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

INK = colors.HexColor("#172033")
MUTED = colors.HexColor("#596579")
NAVY = colors.HexColor("#12345B")
BLUE = colors.HexColor("#2076B8")
CYAN = colors.HexColor("#38B9C7")
PALE_BLUE = colors.HexColor("#EAF4FA")
PALE_CYAN = colors.HexColor("#EAF9F8")
PALE_GOLD = colors.HexColor("#FFF5D9")
GOLD = colors.HexColor("#D59B20")
PAPER = colors.HexColor("#F7F9FC")
WHITE = colors.white
LINE = colors.HexColor("#C9D4E2")

PAGE_W, PAGE_H = A4
MARGIN_X = 17 * mm
MARGIN_TOP = 18 * mm
MARGIN_BOTTOM = 16 * mm
CONTENT_W = PAGE_W - 2 * MARGIN_X


def styles():
    base = getSampleStyleSheet()
    return {
        "h1": ParagraphStyle(
            "h1",
            parent=base["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=25,
            textColor=NAVY,
            spaceAfter=7 * mm,
        ),
        "h2": ParagraphStyle(
            "h2",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=16,
            textColor=BLUE,
            spaceBefore=3 * mm,
            spaceAfter=2 * mm,
        ),
        "body": ParagraphStyle(
            "body",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=9.3,
            leading=12.3,
            textColor=INK,
            spaceAfter=2.4 * mm,
        ),
        "small": ParagraphStyle(
            "small",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=8,
            leading=10.3,
            textColor=MUTED,
        ),
        "callout": ParagraphStyle(
            "callout",
            parent=base["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=9.4,
            leading=12.5,
            textColor=NAVY,
        ),
        "mono": ParagraphStyle(
            "mono",
            parent=base["Code"],
            fontName="Courier",
            fontSize=7.6,
            leading=10,
            textColor=INK,
        ),
        "table": ParagraphStyle(
            "table",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=7.8,
            leading=9.7,
            textColor=INK,
        ),
        "table_head": ParagraphStyle(
            "table_head",
            parent=base["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=7.8,
            leading=9.7,
            textColor=WHITE,
        ),
        "cover_title": ParagraphStyle(
            "cover_title",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=31,
            leading=34,
            alignment=TA_LEFT,
            textColor=WHITE,
        ),
        "cover_sub": ParagraphStyle(
            "cover_sub",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=14,
            leading=19,
            textColor=colors.HexColor("#D8EEF6"),
        ),
        "cover_label": ParagraphStyle(
            "cover_label",
            parent=base["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=11,
            textColor=CYAN,
            tracking=1.2,
        ),
    }


S = styles()


def p(text: str, style: str = "body") -> Paragraph:
    return Paragraph(text, S[style])


def bullet(text: str) -> Paragraph:
    return Paragraph(f"<bullet>&bull;</bullet>{text}", S["body"])


def callout(text: str, background=PALE_CYAN, accent=CYAN):
    table = Table([[p(text, "callout")]], colWidths=[CONTENT_W])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), background),
                ("BOX", (0, 0), (-1, -1), 0.7, accent),
                ("LINEBEFORE", (0, 0), (0, -1), 4, accent),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return table


def code_box(lines: list[str], width=CONTENT_W):
    content = "<br/>".join(line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") for line in lines)
    table = Table([[p(content, "mono")]], colWidths=[width])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EEF2F7")),
                ("BOX", (0, 0), (-1, -1), 0.6, LINE),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    return table


def data_table(headers: list[str], rows: list[list[str]], widths: list[float]):
    data = [[p(cell, "table_head") for cell in headers]]
    data.extend([[p(cell, "table") for cell in row] for row in rows])
    table = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, PAPER]),
                ("GRID", (0, 0), (-1, -1), 0.45, LINE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def section(title: str, kicker: str):
    return [p(kicker.upper(), "small"), p(title, "h1")]


def header_footer(canvas, doc):
    canvas.saveState()
    if doc.page == 1:
        canvas.setFillColor(NAVY)
        canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
        canvas.setFillColor(BLUE)
        canvas.circle(PAGE_W - 12 * mm, PAGE_H - 20 * mm, 48 * mm, fill=1, stroke=0)
        canvas.setFillColor(CYAN)
        canvas.circle(PAGE_W - 20 * mm, PAGE_H - 12 * mm, 15 * mm, fill=1, stroke=0)
    else:
        canvas.setStrokeColor(LINE)
        canvas.setLineWidth(0.5)
        canvas.line(MARGIN_X, PAGE_H - 11 * mm, PAGE_W - MARGIN_X, PAGE_H - 11 * mm)
        canvas.setFont("Helvetica-Bold", 7.5)
        canvas.setFillColor(NAVY)
        canvas.drawString(MARGIN_X, PAGE_H - 8 * mm, "USB GADGET ARCHITECTURE")
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawRightString(PAGE_W - MARGIN_X, PAGE_H - 8 * mm, "CURRENT VERSION-1 CONTRACT")

    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(WHITE if doc.page == 1 else MUTED)
    canvas.drawString(MARGIN_X, 8 * mm, "virtual-yubikey / usb-gadget-supervisor / virtual-trezor")
    canvas.drawRightString(PAGE_W - MARGIN_X, 8 * mm, str(doc.page))
    canvas.restoreState()


def cover(story):
    story.extend(
        [
            Spacer(1, 35 * mm),
            p("ARCHITECTURE GUIDE", "cover_label"),
            Spacer(1, 4 * mm),
            p("Linux USB gadget mode<br/>as a process boundary", "cover_title"),
            Spacer(1, 9 * mm),
            p(
                "ConfigFS, FunctionFS, the UDC, descriptor-driven endpoint discovery, "
                "file-descriptor capabilities, and disposable device workers.",
                "cover_sub",
            ),
            Spacer(1, 26 * mm),
            Table(
                [
                    [p("01", "cover_label"), p("The supervisor constructs and binds the device.", "cover_sub")],
                    [p("02", "cover_label"), p("The worker receives open USB resources, never privileged paths.", "cover_sub")],
                    [p("03", "cover_label"), p("The kernel carries payloads directly between host and worker.", "cover_sub")],
                    [p("04", "cover_label"), p("Worker exit is the complete reconnect and reset primitive.", "cover_sub")],
                ],
                colWidths=[13 * mm, CONTENT_W - 13 * mm],
                rowHeights=[18 * mm] * 4,
                style=TableStyle(
                    [
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("LINEBELOW", (0, 0), (-1, -2), 0.4, colors.HexColor("#45617F")),
                        ("LEFTPADDING", (0, 0), (-1, -1), 0),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ]
                ),
            ),
            Spacer(1, 12 * mm),
            p("Offline companion to docs/usb-gadget-architecture.md", "cover_label"),
            PageBreak(),
        ]
    )


def page_terms(story):
    story.extend(section("The four layers", "01 / mental model"))
    story.append(
        data_table(
            ["Layer", "What it is", "Responsibility"],
            [
                ["UDC", "USB Device Controller hardware + Linux driver", "Moves electrical USB traffic and exposes one bindable controller name."],
                ["ConfigFS", "Kernel configuration filesystem", "Builds the host-visible gadget: identity, configurations, function links, and UDC binding."],
                ["FunctionFS", "Kernel API exposed as files", "Accepts interface descriptors on <font name='Courier'>ep0</font>, creates endpoint files, and reports runtime events."],
                ["Worker", "Unprivileged device implementation", "Handles CTAP, CCID, Trezor messages, crypto, policy, display, buttons, and state."],
            ],
            [24 * mm, 54 * mm, CONTENT_W - 78 * mm],
        )
    )
    story += [Spacer(1, 5 * mm), p("The resulting stack", "h2")]
    story.append(
        code_box(
            [
                "host application / OS class driver",
                "              | USB packets",
                "              v",
                "physical link -> UDC -> composite gadget",
                "                              |",
                "                   FunctionFS endpoint FDs",
                "                              |",
                "                              v",
                "                    unprivileged worker",
            ]
        )
    )
    story += [Spacer(1, 5 * mm)]
    story.append(callout("ConfigFS describes and assembles the device. FunctionFS supplies user-space interfaces. The UDC makes the assembled gadget electrically present to the host."))
    story += [Spacer(1, 4 * mm), p("Binding is the last privileged action", "h2")]
    story.append(p("The gadget remains invisible while it is being constructed. Writing the selected UDC name to the gadget's ConfigFS <font name='Courier'>UDC</font> attribute is the logical equivalent of plugging in the cable. Writing an empty value disconnects it."))
    story.append(PageBreak())


def page_descriptors(story):
    story.extend(section("Descriptors become capabilities", "02 / construction"))
    story.append(p("The worker constructs a typed USB personality and sends it as CBOR in a Configure record. The root-owned profile describes launch arguments and approved local resources. The supervisor validates the personality, creates ConfigFS and FunctionFS, publishes descriptors, and opens the resulting endpoint files."))
    story.append(data_table(
        ["Declaration", "Supervisor responsibility", "Worker receives"],
        [
            ["Device identity", "Publish VID/PID, strings and configuration", "Its accepted generation"],
            ["Interface and endpoint map", "Validate directions, types and packet sizes", "Typed endpoint metadata and FDs"],
            ["FunctionFS descriptors", "Write descriptor and string blobs to ep0", "Only data endpoints"],
            ["Local named resources", "Open approved SPI/I2C devices and exact GPIO line groups", "Narrow resource handles"],
        ], [39 * mm, 58 * mm, CONTENT_W - 97 * mm]))
    story += [Spacer(1, 5 * mm), p("The supervisor retains ep0", "h2")]
    story.append(p("FunctionFS ep0 remains the privileged control plane. The supervisor reads bind, enable, disable, unbind, suspend and resume events and forwards typed UsbBusEvent records. Setup requests arrive at the worker as UsbControlRequest records; the worker sends UsbControlResponse records without owning ep0."))
    story.append(p("The complete USB declaration exists before binding. Runtime control replies are protocol responses, not late descriptor publication. Both YubiKey FIDO HID and CCID use one FunctionFS composite function."))
    story.append(callout("The worker defines the device; the supervisor validates and publishes it. Application payloads then travel directly through data endpoint FDs.", PALE_GOLD, GOLD))
    story.append(PageBreak())


def page_protocol(story):
    story.extend(section("A typed resource protocol", "03 / file-descriptor handoff"))
    story.append(p("An AF_UNIX/SOCK_SEQPACKET socket is installed on fixed worker FD 3. UGSP version 1 records have a 20-byte header plus a bounded body. SCM_RIGHTS carries the declared count of attached descriptors. Generation and request identifiers prevent stale control replies from crossing incarnations."))
    story.append(code_box(["0..3   magic: UGSP", "4      version: 1", "5      message kind", "6..7   attached FD count", "8..11  generation", "12..15 request identifier", "16..19 body length", "20..   body (CBOR for declarations)"]))
    story += [Spacer(1, 3 * mm)]
    story.append(data_table(
        ["Direction", "Record", "Purpose"],
        [
            ["Supervisor -> worker", "InitialResources", "Named, approved local resources"],
            ["Worker -> supervisor", "Configure", "Typed USB personality"],
            ["Supervisor -> worker", "UsbEndpoints", "Endpoint metadata and data FDs"],
            ["Worker -> supervisor", "Serving", "Ready before UDC binding"],
            ["Supervisor -> worker", "UsbBusEvent / UsbControlRequest", "Lifecycle and setup"],
            ["Worker -> supervisor", "UsbControlResponse", "Setup reply"],
            ["Both directions", "Quiesce / Quiesced", "Stop endpoint work and flush"],
        ], [42 * mm, 64 * mm, CONTENT_W - 106 * mm]))
    story += [Spacer(1, 4 * mm)]
    story.append(p("A transferred FD references the same open file description, including access mode and shared offsets. It grants only the operations supported by that handle. GPIO resources contain exact claimed line groups; the worker never receives a broad GPIO-chip FD."))
    story.append(callout("The cleared environment carries state/runtime directory paths, not resource descriptor numbers. Handles arrive through the control socket."))
    story.append(PageBreak())


def page_lifecycle(story):
    story.extend(section("One worker, one incarnation", "04 / lifecycle"))
    story.append(code_box([
        "START WORKER with reduced credentials",
        "       | InitialResources",
        "       v",
        "AWAIT Configure + UsbPersonality",
        "       | validate; create ConfigFS / FunctionFS",
        "       v",
        "SEND UsbEndpoints + data FDs",
        "       |",
        "       v",
        "AWAIT Serving -> bind UDC -> HOST ENUMERATION",
        "       |",
        "       +-> forward lifecycle / setup on control socket",
        "       | worker exit / EOF",
        "       v",
        "CLEAN: unbind, close, reap, unmount, remove",
        "       +-> fresh worker incarnation",
        "service stop: clean -> supervisor exits",
    ]))
    story += [Spacer(1, 5 * mm)]
    story.append(p("Serving means the worker has validated the endpoint map and initialized its protocol state. Only then does the supervisor bind the UDC. Virtual YubiKey receives five FunctionFS data endpoints: two FIDO interrupt endpoints and three CCID endpoints. There is no separate post-bind ConfigFS HID handoff."))
    story.append(p("The supervisor retains ep0 and forwards lifecycle and setup records. The worker handles ordinary protocol traffic directly on its endpoint handles. Quiesce stops endpoint work and flushes durable state before a controlled teardown."))
    story.append(p("A firmware reconnect is worker exit. The supervisor unbinds first, destroys the incarnation, and launches a fresh Unix process. A service stop performs final cleanup and exits."))
    story.append(callout("Process creation is the reset primitive for volatile threads, buffers and capabilities. Persistent applet records survive ordinary restart."))
    story.append(PageBreak())


def page_data_paths(story):
    story.extend(section("The supervisor leaves the data plane", "05 / device workers"))
    story.append(p("After startup, the kernel moves USB payloads directly between the host controller and worker-held FDs. The privileged process handles metadata and lifecycle only; it never sees CTAP frames, APDUs, Trezor protobuf messages, PINs, seeds, keys, or YubiHSM commands."))
    story.append(
        data_table(
            ["Device", "Kernel surface", "Worker traffic"],
            [
                ["Virtual YubiKey", "FunctionFS HID + CCID", "FIDO reports and CCID data endpoints; setup over the control socket"],
                ["Virtual Trezor", "FunctionFS vendor interface", "64-byte interrupt OUT/IN packets; forwarded setup and lifecycle"],
                ["Virtual YubiHSM", "FunctionFS vendor bulk interface", "Bulk request/response frames; forwarded setup and lifecycle"],
            ],
            [33 * mm, 53 * mm, CONTENT_W - 86 * mm],
        )
    )
    story += [Spacer(1, 5 * mm), p("Virtual YubiKey", "h2")]
    story.append(p("The shared core implements Management, FIDO2, PIV, OpenPGP, YubiHSM Auth, and Issuer Security Domain. GlobalPlatform SCP03/SCP11a/b/c protects every selectable CCID applet. HID and CCID FIDO routes share one authenticator; embedded readers use the same core and per-applet storage runtime."))
    story.append(p("The worker advertises the compatibility manufacturer Yubico and product YubiKey Gadget FIDO+CCID for controlled local testing. Gadget distinguishes the virtual reader. Host tools include browsers, ykman, yubico-piv-tool, GnuPG and pkcs11rs. This identity does not imply vendor endorsement."))
    story += [Spacer(1, 2 * mm), p("Virtual Trezor", "h2")]
    story.append(p("The worker owns its USB personality and direct OUT/IN endpoint traffic. Named display and button resources are restricted to the profile's declared device and GPIO line groups. Upstream firmware composes the 128x64 framebuffer; button handling uses edge events and atomic snapshots. Orderly exit clears the display."))
    story += [Spacer(1, 2 * mm), p("Virtual YubiHSM", "h2")]
    story.append(p("The same FunctionFS pattern supports a vendor bulk device. Its worker supplies the USB personality and owns commands, sessions, objects, capabilities, audit behavior, and state. The supervisor needs no YubiHSM-specific code."))
    story.append(PageBreak())


def page_host(story):
    story.extend(section("What the host actually talks to", "06 / client behavior"))
    story.append(p("There is no extra network client or server. To macOS, Linux, or Windows the Raspberry Pi is an ordinary USB peripheral. Host class drivers claim interfaces and expose their normal APIs to applications."))
    story.append(
        data_table(
            ["USB interface", "Host-side path", "Typical application"],
            [
                ["HID / FIDO", "OS HID + FIDO stack", "Browser, WebAuthn client, libfido2"],
                ["CCID", "USB CCID driver + PC/SC", "ykman, GnuPG, OpenSC, pkcs11rs"],
                ["Trezor vendor interface", "Trezor transport library", "trezorctl, Trezor Suite"],
                ["Vendor bulk", "libusb or product library", "YubiHSM connector/client"],
            ],
            [42 * mm, 59 * mm, CONTENT_W - 101 * mm],
        )
    )
    story += [Spacer(1, 5 * mm), p("Why FIDO can work while CCID is exclusive", "h2")]
    story.append(p("HID does not inherently make a device shareable. FIDO and CCID remain independently usable because they are separate USB interfaces claimed by separate host-driver stacks. An application's exclusive PC/SC transaction on the CCID interface does not claim the HID interface."))
    story.append(p("The same distinction applies inside the worker: each interface has different framing and endpoint semantics even when both ultimately reach applets in one virtual device. HID is report-oriented and host-polled; CCID and vendor protocols use their declared bulk or interrupt endpoints."))
    story.append(callout("The host never knows about ConfigFS, FunctionFS, SCM_RIGHTS, or worker processes. Those are Linux implementation details behind the USB identity it enumerates.", PALE_BLUE, BLUE))
    story.append(PageBreak())


def page_pi(story):
    story.extend(section("Pi 4 and Pi 5 use the same model", "07 / UDC discovery"))
    story.append(p("The deployment is tested on both 64-bit Ubuntu and 64-bit Raspberry Pi OS. On either system, the normal board-specific setup is to enable DWC2 in peripheral mode; the supervisor then uses the resulting UDC through ConfigFS and FunctionFS."))
    story.append(p("USB gadget mode depends on a USB Device Controller, not on I2C target/peripheral support. Raspberry Pi 4 and Pi 5 both use Linux DWC2 device mode on the gadget-capable USB-C connection. The Pi 5's ordinary RP1 USB host ports are not extra gadget controllers."))
    story += [Spacer(1, 3 * mm)]
    story.append(code_box([
        "/sys/class/udc/",
        "  fe980000.usb       # typical Pi 4 name",
        "  1000480000.usb     # typical Pi 5 name",
        "",
        "supervisor: sort names -> choose first",
        'profile:    udc = "EXACT_NAME"',
    ]))
    story += [Spacer(1, 5 * mm), p("When can more than one UDC exist?", "h2")]
    for item in [
        "A test system loads dummy_hcd and exposes one or more software controllers.",
        "A virtualized or emulated platform supplies several device controllers.",
        "Custom carrier hardware exposes an additional physical device-mode controller.",
        "A non-Pi system genuinely contains multiple gadget-capable controllers.",
    ]:
        story.append(bullet(item))
    story.append(p("One selected UDC exposes one profile at a time. Virtual YubiKey and Virtual Trezor can both be installed, but two simultaneously enumerated identities require two independent controllers or two Pis."))
    story += [Spacer(1, 2 * mm), p("Power and the host port", "h2")]
    story.append(p("A Pi 5 can draw substantial power compared with a small USB token. Gadget-mode software does not protect against an inadequate cable, supply, or host-port power budget. A separately powered Pi may still use the data connection, but power topology must avoid unintended back-power paths and follow the board's electrical guidance."))
    story.append(callout("UDC names are discovered from sysfs because they are kernel/hardware identifiers, not stable product names to hard-code in a worker."))
    story.append(PageBreak())


def page_security(story):
    story.extend(section("The installed contract", "08 / operations and trust"))
    story.append(
        data_table(
            ["Artifact", "Owner", "Current contract"],
            [
                ["Profile", "Device project; root-installed", "Schema 1; worker launch and approved named hardware resources"],
                ["Supervisor", "Privileged service", "Validate, construct, open, transfer, bind, monitor, unbind, clean"],
                ["Worker protocol", "Matched deployment set", "UGSP version 1; 20-byte headers, typed bodies, generation and request IDs"],
                ["Worker", "Unprivileged device project", "Protocol logic, secrets, state, UI, and direct endpoint I/O"],
            ],
            [32 * mm, 47 * mm, CONTENT_W - 79 * mm],
        )
    )
    story += [Spacer(1, 5 * mm), p("Capability boundary", "h2")]
    story.append(p("The worker receives open resources, not permission to explore privileged namespaces. FunctionFS remains root-owned, and raw GPIO-chip resources are rejected. The control socket is fixed at FD 3; every other handle arrives through <font name='Courier'>SCM_RIGHTS</font>. The supervisor closes its transferred copies after handoff, while worker process death closes the final copies automatically. The cleared environment contains only the persistent and runtime directory paths, while configured worker options remain command arguments."))
    story.append(p("This is useful privilege separation, not hardware isolation. A software authenticator or wallet on a general-purpose Pi remains vulnerable to compromise of its worker account, kernel, storage, memory, supply chain, and physical environment."))
    story += [Spacer(1, 2 * mm), p("Operational checks", "h2")]
    for item in [
        "Validate the profile before installation and keep the installed copy root-owned.",
        "Confirm endpoint count, order, direction, and host-visible interface order.",
        "Observe Configure, UsbEndpoints, Serving, UDC bind, USB activation and teardown logs.",
        "Kill the worker and verify unbind-first cleanup followed by a fresh process.",
        "Stop the service and verify final UDC, ConfigFS, mount, display, and process cleanup.",
    ]:
        story.append(bullet(item))
    story += [Spacer(1, 3 * mm)]
    story.append(callout("The design is deliberately literal: a virtual firmware implementation reads and writes real kernel endpoint file descriptors. The supervisor supplies those capabilities and controls when the host can see them."))
    story += [Spacer(1, 5 * mm), HRFlowable(width="100%", thickness=0.6, color=LINE), Spacer(1, 3 * mm)]
    story.append(p("Detailed, browser-readable documentation: docs/usb-gadget-architecture.md", "small"))


def build(output: Path):
    output.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(output),
        pagesize=A4,
        leftMargin=MARGIN_X,
        rightMargin=MARGIN_X,
        topMargin=MARGIN_TOP,
        bottomMargin=MARGIN_BOTTOM,
        title="Linux USB Gadget Architecture",
        author="virtual-yubikey project",
        subject="Current version-1 usb-gadget-supervisor worker architecture",
    )
    story = []
    cover(story)
    page_terms(story)
    page_descriptors(story)
    page_protocol(story)
    page_lifecycle(story)
    page_data_paths(story)
    page_host(story)
    page_pi(story)
    page_security(story)
    doc.build(story, onFirstPage=header_footer, onLaterPages=header_footer)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("output/pdf/usb-gadget-architecture.pdf"),
    )
    args = parser.parse_args()
    build(args.output)


if __name__ == "__main__":
    main()
