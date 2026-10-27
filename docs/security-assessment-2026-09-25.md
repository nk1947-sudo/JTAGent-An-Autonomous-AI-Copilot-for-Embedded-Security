# BeagleBone Black controlled security assessment

Date: 2026-09-25  
Target: Authorized local BeagleBone Black (AM335x-GP rev 2.1)  
Interfaces: C232HM JTAG and TTL-232R-RPi UART0  
Method: Read-only observation and identity checks; no firmware, environment, storage or memory writes

## Executive summary

The target exposes a serial login using the vendor-default account and grants that account
non-interactive root access through `sudo`. This establishes root impact for an attacker with physical
UART access. JTAG also remains operational after boot and can halt the CPU and capture approved memory
and registers. The bootloader advertises an unauthenticated autoboot interruption window, but that
specific U-Boot prompt was observed rather than interrupted during this assessment.

No persistence, payload execution, destructive command, configuration change or exploit installation
was attempted. The serial session was logged out after validation.

## FIND-001 — Vendor-default UART account reaches root

- Severity: High
- Confidence: High
- Status: Validated
- Access required: Physical access to the 3.3 V UART0 header

### Evidence

The boot console displayed a default username/password notice. The advertised account successfully
authenticated over UART. Read-only identity checks returned:

```text
uid=1000(debian) gid=1000(debian) ... groups include admin
3.8.13-bone80
```

A non-interactive privilege check returned:

```text
sudo -n id
uid=0(root) gid=0(root) groups=0(root)
```

The password itself is deliberately omitted from this report. It was not added to source control.

### Impact

Anyone with physical access to the exposed UART header can obtain an operating-system shell and then
root privileges using publicly advertised default credentials. Root access permits complete
confidentiality, integrity and availability compromise of the device and its stored data.

### Recommended remediation

1. Remove or lock the default account during provisioning and require a unique credential per device.
2. Remove passwordless `sudo`; grant only the minimum maintenance commands required.
3. Disable the production serial login service, or place it behind an authenticated maintenance mode.
4. Treat deployed devices using this image as requiring credential rotation and forensic review.

## FIND-002 — JTAG remains active after normal boot

- Severity: High for a production device; informational for an intentionally open development board
- Confidence: High
- Status: Validated
- Access required: Physical access to the CTI JTAG header

### Evidence

OpenOCD identified the AM335x scan chain and Cortex-A8 debug target. While the operating system was
running, an authenticated policy-bounded audit halted the CPU, captured 64 bytes of approved SRAM plus
`pc`, `lr`, `sp` and `cpsr`, and restored the CPU to running in 1293.26 ms. Recovery was not required.

### Impact

An exposed production debug port can bypass operating-system access controls, inspect execution state
and interrupt availability. The current bridge disables unrestricted writes, but that local software
policy does not constrain another physical debugger.

### Recommended remediation

Define whether production devices require hardware debug. If not, disable or lifecycle-lock JTAG using
the SoC/vendor-supported mechanism, remove or depopulate the connector, and add physical tamper controls.
Verify the final production state independently; do not infer hardware locking from API policy.

## FIND-003 — U-Boot exposes an autoboot interruption window

- Severity: Medium pending command-prompt validation
- Confidence: High that the window exists; unverified command access
- Status: Observed

### Evidence

UART boot output included:

```text
U-Boot 2019.04-00002-gf15b99f0b6
Press SPACE to abort autoboot in 2 seconds
```

The assessment did not interrupt boot, change variables or issue U-Boot commands.

### Impact

If interruption exposes an unrestricted prompt, a local attacker may alter boot arguments, select
alternate media or bypass normal operating-system startup controls.

### Recommended verification and remediation

On a recoverable image, interrupt one boot and execute only `version`, `bdinfo`, `printenv` and `help`.
For production, remove the interruption window or require authenticated maintenance access. Protect
boot configuration and use a verified/signed boot chain appropriate to the deployment threat model.

## FIND-004 — Legacy operating-system and boot stack

- Severity: Medium
- Confidence: High
- Status: Observed; no CVE applicability analysis performed

### Evidence

The target reported a 2016 Debian image, Linux `3.8.13-bone80`, and U-Boot 2019.04. Boot also loaded
`/uEnv.txt` from removable/storage media and executed `uenvcmd`.

### Impact

The age of the stack substantially increases patch-management risk. Loading mutable external boot
configuration may also weaken boot integrity when storage is attacker-controlled. These observations
do not by themselves prove a specific exploitable CVE or boot bypass.

### Recommended remediation

Move to a supported image and kernel, inventory applicable vulnerabilities, minimize enabled services,
and validate signed boot artifacts and protected boot configuration before treating the device as a
production trust boundary.

## Limitations

- Physical-access scope only; no network services were tested.
- The U-Boot prompt was not interrupted, so command availability is not yet established.
- No independent secure-boot/fuse-state attestation was performed.
- No password hashes, private keys, firmware images or raw live memory were exported.
- The observed EXT4 journal error is an operational concern and was not classified as a security issue.
