# Security Policy

Virtual YubiKey is experimental compatibility software, not a security device.
It has not been released as stable, independently audited, or designed to
protect production credentials.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private
vulnerability reporting feature for this repository. Include the affected
protocol or component, expected impact, reproduction details, and any suggested
mitigation.

Issues in privileged ConfigFS, FunctionFS, UDC, profile-validation, or worker
lifecycle behavior belong in the `usb-gadget-supervisor` repository.

## Security expectations

Keys and credentials are stored and processed by ordinary software on a
general-purpose computer. This project provides none of the secure-element,
tamper-resistance, extraction-resistance, or trusted-presence guarantees of a
physical security token. Use only test credentials and test accounts.
