# Rule catalog

Every rule shipped in this repository, by platform directory. The ATT&CK column lists the
technique tags of each rule. For coverage across the agent's native rules, the correlator and this
repository together, see the agent's generated
[ATT&CK coverage page](https://github.com/synthaea-lab/agent/blob/main/docs/attack-coverage.md).

The "Lineage" column marks rules that key on `ParentImage`. They cannot fire on an event whose
sensor supplied no parent image.

This page is maintained by hand: update it in the same pull request that adds, removes or retitles
a rule.

## Linux and macOS (`sigma/linux/`)

| Rule | Title | Level | ATT&CK | Lineage |
| --- | --- | --- | --- | --- |
| [`audit_collection_disabled`](../sigma/linux/audit_collection_disabled.yml) | Linux audit collection explicitly disabled with auditctl | medium | T1562.001 | no |
| [`audit_service_masked_now`](../sigma/linux/audit_service_masked_now.yml) | Linux audit daemon masked and stopped immediately | medium | T1562.001 | no |
| [`base64_pipe_shell`](../sigma/linux/base64_pipe_shell.yml) | Base64-encoded command piped to a shell | high | T1059.004, T1027 | no |
| [`browser_spawned_shell`](../sigma/linux/browser_spawned_shell.yml) | Browser spawned a shell | medium | T1189, T1059.004 | yes |
| [`curl_upload_to_cloud_storage`](../sigma/linux/curl_upload_to_cloud_storage.yml) | Linux curl uploads a file to a cloud storage endpoint | medium | T1567.002 | no |
| [`curl_upload_to_paste_service`](../sigma/linux/curl_upload_to_paste_service.yml) | Linux curl uploads a file to a paste service | medium | T1567.003 | no |
| [`lolbin_shell_breakout`](../sigma/linux/lolbin_shell_breakout.yml) | GTFOBins - system binary used to spawn a shell | high | T1059.004, T1548 | no |
| [`passworded_home_archive`](../sigma/linux/passworded_home_archive.yml) | Passworded archive of Linux home data | medium | T1560.001 | no |
| [`persistence`](../sigma/linux/persistence.yml) | Persistence via cron, SSH authorized_keys or systemd service | high | T1053.003, T1098.004, T1543.002 | no |
| [`reverse_shell`](../sigma/linux/reverse_shell.yml) | Reverse shell via /dev/tcp or nc/ncat with execution | critical | T1059.004, T1071 | no |
| [`setcap_shell_uid`](../sigma/linux/setcap_shell_uid.yml) | Setcap grants UID capability to a shell or interpreter | medium | T1548 | no |
| [`shadow_file_copy`](../sigma/linux/shadow_file_copy.yml) | Shadow password database copied with cp | medium | T1003.008 | no |
| [`sudo_vim_shell_escape`](../sigma/linux/sudo_vim_shell_escape.yml) | Sudo launches Vim with an explicit shell escape | medium | T1548.003 | no |
| [`susp_tmp_exec`](../sigma/linux/susp_tmp_exec.yml) | Executable launched from a temporary or world-writable directory | medium | T1059, T1036 | no |
| [`unshadow_live_password_databases`](../sigma/linux/unshadow_live_password_databases.yml) | Unshadow combines live account and password databases | medium | T1003.008 | no |

## Windows (`sigma/windows/`)

| Rule | Title | Level | ATT&CK | Lineage |
| --- | --- | --- | --- | --- |
| [`bitsadmin_upload_job`](../sigma/windows/bitsadmin_upload_job.yml) | BITSAdmin submits an HTTP upload job | medium | T1041 | no |
| [`browser_spawned_interpreter`](../sigma/windows/browser_spawned_interpreter.yml) | Browser spawned a command interpreter | medium | T1189, T1059.001 | yes |
| [`curl_upload_to_cloud_storage`](../sigma/windows/curl_upload_to_cloud_storage.yml) | Windows curl uploads a file to a cloud storage endpoint | medium | T1567.002 | no |
| [`defender_realtime_disable`](../sigma/windows/defender_realtime_disable.yml) | Defender real-time monitoring disabled by PowerShell command | medium | T1562.001 | no |
| [`firewall_allprofiles_disabled`](../sigma/windows/firewall_allprofiles_disabled.yml) | Windows firewall disabled for all profiles | medium | T1562.004 | no |
| [`iis_worker_spawned_interpreter`](../sigma/windows/iis_worker_spawned_interpreter.yml) | IIS worker spawned a command interpreter | medium | T1190, T1059.001 | yes |
| [`lolbas_rundll32`](../sigma/windows/lolbas_rundll32.yml) | Rundll32 with suspicious argument | high | T1218.011 | no |
| [`net_add_local_administrator`](../sigma/windows/net_add_local_administrator.yml) | Net adds an account to the local Administrators group | medium | T1098 | no |
| [`ntds_ifm_export`](../sigma/windows/ntds_ifm_export.yml) | NTDS database exported through install-from-media | medium | T1003.003 | no |
| [`office_spawned_interpreter`](../sigma/windows/office_spawned_interpreter.yml) | Office document spawned a command interpreter | medium | T1204, T1059.001 | yes |
| [`passworded_user_data_archive`](../sigma/windows/passworded_user_data_archive.yml) | Passworded archive of Windows user data | medium | T1560.001 | no |
| [`powershell_add_sid_to_local_group`](../sigma/windows/powershell_add_sid_to_local_group.yml) | PowerShell adds a member to the local Administrators group | medium | T1098 | no |
| [`powershell_encoded`](../sigma/windows/powershell_encoded.yml) | PowerShell Base64-encoded command | medium | T1059.001, T1027 | no |
| [`procdump_lsass_full_dump`](../sigma/windows/procdump_lsass_full_dump.yml) | ProcDump full memory dump targeting LSASS by name | medium | T1003.001 | no |
| [`psexec_remote_inline_credentials`](../sigma/windows/psexec_remote_inline_credentials.yml) | PsExec remote invocation with an inline password | medium | T1021.002 | no |
| [`registry_credential_hive_save`](../sigma/windows/registry_credential_hive_save.yml) | Registry credential hives saved to files | medium | T1003.002, T1003.004 | no |
| [`remote_scheduled_task_system`](../sigma/windows/remote_scheduled_task_system.yml) | Remote scheduled task created to run as SYSTEM | medium | T1053.005 | no |
| [`remote_service_shell_command`](../sigma/windows/remote_service_shell_command.yml) | Remote service created with a command-shell binary path | medium | T1543.003 | no |
| [`security_service_start_disabled`](../sigma/windows/security_service_start_disabled.yml) | Security service configured with disabled startup | medium | T1562.001 | no |
| [`service_created_with_shell_binpath`](../sigma/windows/service_created_with_shell_binpath.yml) | Service created with a command-shell binary path | medium | T1543.003 | no |
| [`susp_appdata_exec`](../sigma/windows/susp_appdata_exec.yml) | Executable from AppData or Temp | low | T1059, T1036 | no |
| [`web_server_spawned_interpreter`](../sigma/windows/web_server_spawned_interpreter.yml) | Web server or application server spawned a command interpreter | medium | T1190, T1059 | yes |
| [`wmic_remote_process_inline_password`](../sigma/windows/wmic_remote_process_inline_password.yml) | WMIC remote process creation with an inline password | medium | T1047 | no |

## macOS only (`sigma/macos/`)

| Rule | Title | Level | ATT&CK | Lineage |
| --- | --- | --- | --- | --- |
| [`web_server_spawned_shell`](../sigma/macos/web_server_spawned_shell.yml) | Web server spawned a shell on macOS | medium | T1190, T1059.004 | yes |

## YARA (`yara/`)

Every host loads every YARA rule.

| Rule | Description | Severity | ATT&CK |
| --- | --- | --- | --- |
| [`synthaea_lab_payload`](../yara/lab/synthaea_lab_payload.yar) | Benign lab payload marker (scenario validation) | low | T1105 |
| [`webshell_jsp_runtime_exec`](../yara/webshell/webshell_jsp_runtime_exec.yar) | JSP Runtime.exec() fed directly from a request parameter - minimal webshell backdoor shape | critical | T1505.003 |
| [`webshell_php_superglobal_exec`](../yara/webshell/webshell_php_superglobal_exec.yar) | PHP code-execution sink fed directly from a request superglobal - minimal webshell backdoor shape | critical | T1505.003 |

## IOC feeds (`ioc/`)

None shipped yet. See [IOC feeds](layout-and-delivery.md#ioc-feeds) for the format.
