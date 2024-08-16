#!/usr/bin/env python3

import argparse
import sys
from pathlib import Path
import json
import os
import random
import string
import requests
import base64

class AutoRecon2Obsidian:

    def __init__(self):
        self.arguments = self.parse_arguments()
        self.autorecon_results_dir = self.arguments.autorecon_dir
        self.obsidian_vault_dir = self.arguments.obsidian_dir
        self.challenge_platform = self.arguments.platform
        self.target_name = self.arguments.name

    def parse_arguments(self):
        parser = argparse.ArgumentParser(
            prog='autorecon2obsidian',
            description='Automatically generate Obsidian-compatible markdown files from a given directory',
            epilog='Examples: autorecon2obsidian /path/to/your/results/directory /path/to/your/obsidian/vault/directory',
        )

        parser.add_argument('autorecon_dir', help='Path to the directory containing your autorecon results')
        parser.add_argument('obsidian_dir', help='Path to the directory containing your obsidian vault')
        parser.add_argument('--platform', choices=['HTB', 'PG', 'PEN200'], default='HTB', help='Challenge platform')
        parser.add_argument('--name', required=True, help='Machine Name')
        return parser.parse_args()

    def gather_autorecon_report_data(self):
        gathered_auto_recon_data = {
            'ports': {
                'tcp': {},
                'udp': {}
            }
        }
        tcp_port_dirs = self._get_port_dirs('tcp')
        udp_port_dirs = self._get_port_dirs('udp')
        for tcp_port_dir in tcp_port_dirs: 
            tcp_port_report_files = self._get_report_files(tcp_port_dir)
            dir_name = tcp_port_dir.name.replace('tcp', '')
            gathered_auto_recon_data['ports']['tcp'][dir_name] = {}
            gathered_auto_recon_data['ports']['tcp'][dir_name]['tools_used'] = []
            gathered_auto_recon_data['ports']['tcp'][dir_name]['directory'] = str(tcp_port_dir)
            gathered_auto_recon_data['ports']['tcp'][dir_name]['name'] = self._get_service_name(tcp_port_dir)
            gathered_auto_recon_data['ports']['tcp'][dir_name]['autorecon_reports'] = {}
            report_ctr = 0
            for report_file in tcp_port_report_files:
                gathered_auto_recon_data['ports']['tcp'][dir_name]['autorecon_reports'][report_ctr] = {}
                gathered_auto_recon_data['ports']['tcp'][dir_name]['autorecon_reports'][report_ctr]['file_name'] = report_file.name
                gathered_auto_recon_data['ports']['tcp'][dir_name]['autorecon_reports'][report_ctr]['file_path'] = str(report_file)
                with open(report_file) as file_handle:
                    gathered_auto_recon_data['ports']['tcp'][dir_name]['autorecon_reports'][report_ctr]['base64_contents'] = base64.b64encode(file_handle.read().encode('ascii')).decode('ascii')
                tool_used = self._get_tool_used(report_file)
                gathered_auto_recon_data['ports']['tcp'][dir_name]['autorecon_reports'][report_ctr]['source_tool'] = tool_used
                gathered_auto_recon_data['ports']['tcp'][dir_name]['autorecon_reports'][report_ctr]['base64_command_used'] = self._get_command_used(report_file)
                current_tools_used = gathered_auto_recon_data['ports']['tcp'][dir_name]['tools_used']
                if tool_used != 'Unknown':
                    if not any(tool_used == x for x in current_tools_used):
                        gathered_auto_recon_data['ports']['tcp'][dir_name]['tools_used'].append(tool_used)
                report_ctr += 1
        for udp_port_dir in udp_port_dirs: 
            udp_port_report_files = self._get_report_files(udp_port_dir)
            dir_name = udp_port_dir.name.replace('udp', '')
            gathered_auto_recon_data['ports']['udp'][dir_name] = {}
            gathered_auto_recon_data['ports']['udp'][dir_name]['tools_used'] = []
            gathered_auto_recon_data['ports']['udp'][dir_name]['directory'] = str(udp_port_dir)
            gathered_auto_recon_data['ports']['udp'][dir_name]['name'] = self._get_service_name(udp_port_dir)
            gathered_auto_recon_data['ports']['udp'][dir_name]['autorecon_reports'] = {}
            report_ctr = 0
            for report_file in udp_port_report_files:
                gathered_auto_recon_data['ports']['udp'][dir_name]['autorecon_reports'][report_ctr] = {}
                gathered_auto_recon_data['ports']['udp'][dir_name]['autorecon_reports'][report_ctr]['file_name'] = report_file.name
                gathered_auto_recon_data['ports']['udp'][dir_name]['autorecon_reports'][report_ctr]['file_path'] = str(report_file)
                with open(report_file) as file_handle:
                    gathered_auto_recon_data['ports']['udp'][dir_name]['autorecon_reports'][report_ctr]['base64_contents'] = base64.b64encode(file_handle.read().encode('ascii')).decode('ascii')
                tool_used = self._get_tool_used(report_file)
                gathered_auto_recon_data['ports']['udp'][dir_name]['autorecon_reports'][report_ctr]['source_tool'] = tool_used
                gathered_auto_recon_data['ports']['udp'][dir_name]['autorecon_reports'][report_ctr]['base64_command_used'] = self._get_command_used(report_file)
                current_tools_used = gathered_auto_recon_data['ports']['udp'][dir_name]['tools_used']
                if tool_used != 'Unknown':
                    if not any(tool_used == x for x in current_tools_used):
                        gathered_auto_recon_data['ports']['udp'][dir_name]['tools_used'].append(tool_used)
                report_ctr += 1
        return gathered_auto_recon_data
    def _get_command_used(self, report_file):

        command_grep = {
            '_smtp_user-enum_hydra_vrfy.txt': 'aHlkcmEgc210cC1lbnVtOi8ve2FkZHJlc3N2Nn06e3BvcnR9L3ZyZnkgLUwgIicgKyBzZWxmLmdldF9nbG9iYWwoJ3VzZXJuYW1lX3dvcmRsaXN0JywgZGVmYXVsdD0nL3Vzci9zaGFyZS9zZWNsaXN0cy9Vc2VybmFtZXMvdG9wLXVzZXJuYW1lcy1zaG9ydGxpc3QudHh0JykgKyAnIiAyPiYxJywgb3V0ZmlsZT0ne3Byb3RvY29sfV97cG9ydH1fc210cF91c2VyLWVudW1faHlkcmFfdnJmeS50eHQnKQo=',
            '_smtp_user-enum_hydra_expn.txt': 'aHlkcmEgc210cC1lbnVtOi8ve2FkZHJlc3N2Nn06e3BvcnR9L2V4cG4gLUwgIicgKyBzZWxmLmdldF9nbG9iYWwoJ3VzZXJuYW1lX3dvcmRsaXN0JywgZGVmYXVsdD0nL3Vzci9zaGFyZS9zZWNsaXN0cy9Vc2VybmFtZXMvdG9wLXVzZXJuYW1lcy1zaG9ydGxpc3QudHh0JykgKyAnIiAyPiYxJywgb3V0ZmlsZT0ne3Byb3RvY29sfV97cG9ydH1fc210cF91c2VyLWVudW1faHlkcmFfZXhwbi50eHQnKQo=',
            '_mysql_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLChteXNxbCogb3Igc3NsKikgYW5kIG5vdCAoYnJ1dGUgb3IgYnJvYWRjYXN0IG9yIGRvcyBvciBleHRlcm5hbCBvciBmdXp6ZXIpIiAtb04gIntzY2FuZGlyfS97cHJvdG9jb2x9X3twb3J0fV9teXNxbF9ubWFwLnR4dCIgLW9YICJ7c2NhbmRpcn0veG1sL3twcm90b2NvbH1fe3BvcnR9X215c3FsX25tYXAueG1sIiB7YWRkcmVzc30nKQo=',
            'enum4linux.txt': 'ZW51bTRsaW51eCAtYSAtTSAtbCAtZCB7YWRkcmVzc30gMj4mMScsIG91dGZpbGU9J2VudW00bGludXgudHh0JykK',
            'enum4linux-ng.txt': 'ZW51bTRsaW51eC1uZyAtQSAtZCAtdiB7YWRkcmVzc30gMj4mMScsIG91dGZpbGU9J2VudW00bGludXgtbmcudHh0JykK',
            '_oracle_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLChvcmFjbGUqIG9yIHNzbCopIGFuZCBub3QgKGJydXRlIG9yIGJyb2FkY2FzdCBvciBkb3Mgb3IgZXh0ZXJuYWwgb3IgZnV6emVyKSIgLW9OICJ7c2NhbmRpcn0ve3Byb3RvY29sfV97cG9ydH1fb3JhY2xlX25tYXAudHh0IiAtb1ggIntzY2FuZGlyfS94bWwve3Byb3RvY29sfV97cG9ydH1fb3JhY2xlX25tYXAueG1sIiB7YWRkcmVzc30nKQo=',
            '_rpc_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLG1zcnBjLWVudW0scnBjLWdyaW5kLHJwY2luZm8iIC1vTiAie3NjYW5kaXJ9L3twcm90b2NvbH1fe3BvcnR9X3JwY19ubWFwLnR4dCIgLW9YICJ7c2NhbmRpcn0veG1sL3twcm90b2NvbH1fe3BvcnR9X3JwY19ubWFwLnhtbCIge2FkZHJlc3N9JykK',
            '_pop3_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLChwb3AzKiBvciBzc2wqKSBhbmQgbm90IChicnV0ZSBvciBicm9hZGNhc3Qgb3IgZG9zIG9yIGV4dGVybmFsIG9yIGZ1enplcikiIC1vTiAie3NjYW5kaXJ9L3twcm90b2NvbH1fe3BvcnR9X3BvcDNfbm1hcC50eHQiIC1vWCAie3NjYW5kaXJ9L3htbC97cHJvdG9jb2x9X3twb3J0fV9wb3AzX25tYXAueG1sIiB7YWRkcmVzc30nKQo=',
            '_dns_zone-transfer-domain.txt': 'ZGlnIEFYRlIgLXAge3BvcnR9IEB7YWRkcmVzc30gJyArIHNlbGYuZ2V0X2dsb2JhbCgnZG9tYWluJyksIG91dGZpbGU9J3twcm90b2NvbH1fe3BvcnR9X2Ruc196b25lLXRyYW5zZmVyLWRvbWFpbi50eHQnKQo=',
            '_dns_zone-transfer-hostname.txt': 'ZGlnIEFYRlIgLXAge3BvcnR9IEB7YWRkcmVzc30ge2FkZHJlc3N9Jywgb3V0ZmlsZT0ne3Byb3RvY29sfV97cG9ydH1fZG5zX3pvbmUtdHJhbnNmZXItaG9zdG5hbWUudHh0JykK',
            '_dns_zone-transfer.txt': 'ZGlnIEFYRlIgLXAge3BvcnR9IEB7YWRkcmVzc30nLCBvdXRmaWxlPSd7cHJvdG9jb2x9X3twb3J0fV9kbnNfem9uZS10cmFuc2Zlci50eHQnKQo=',
            '_oracle_tnscmd_ping.txt': 'dG5zY21kMTBnIHBpbmcgLWgge2FkZHJlc3N9IC1wIHtwb3J0fSAyPiYxJywgb3V0ZmlsZT0ne3Byb3RvY29sfV97cG9ydH1fb3JhY2xlX3Ruc2NtZF9waW5nLnR4dCcpCg==',
            '_oracle_tnscmd_version.txt': 'dG5zY21kMTBnIHZlcnNpb24gLWgge2FkZHJlc3N9IC1wIHtwb3J0fSAyPiYxJywgb3V0ZmlsZT0ne3Byb3RvY29sfV97cG9ydH1fb3JhY2xlX3Ruc2NtZF92ZXJzaW9uLnR4dCcpCg==',
            '_redis_info.txt': 'cmVkaXMtY2xpIC1wIHtwb3J0fSAtaCB7YWRkcmVzc30gSU5GTycsIG91dGZpbGU9J3twcm90b2NvbH1fe3BvcnR9X3JlZGlzX2luZm8udHh0JykK',
            '_redis_config.txt': 'cmVkaXMtY2xpIC1wIHtwb3J0fSAtaCB7YWRkcmVzc30gQ09ORklHIEdFVCBcJypcJycsIG91dGZpbGU9J3twcm90b2NvbH1fe3BvcnR9X3JlZGlzX2NvbmZpZy50eHQnKQo=',
            '_redis_client-list.txt': 'cmVkaXMtY2xpIC1wIHtwb3J0fSAtaCB7YWRkcmVzc30gQ0xJRU5UIExJU1QnLCBvdXRmaWxlPSd7cHJvdG9jb2x9X3twb3J0fV9yZWRpc19jbGllbnQtbGlzdC50eHQnKQo=',
            '_rsync_file_list.txt': 'cnN5bmMgLWF2IC0tbGlzdC1vbmx5IHJzeW5jOi8ve2FkZHJlc3N2Nn06e3BvcnR9Jywgb3V0ZmlsZT0ne3Byb3RvY29sfV97cG9ydH1fcnN5bmNfZmlsZV9saXN0LnR4dCcpCg==',
            '_vnc_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLCh2bmMqIG9yIHJlYWx2bmMqIG9yIHNzbCopIGFuZCBub3QgKGJydXRlIG9yIGJyb2FkY2FzdCBvciBkb3Mgb3IgZXh0ZXJuYWwgb3IgZnV6emVyKSIgLS1zY3JpcHQtYXJncz0idW5zYWZlPTEiIC1vTiAie3NjYW5kaXJ9L3twcm90b2NvbH1fe3BvcnR9X3ZuY19ubWFwLnR4dCIgLW9YICJ7c2NhbmRpcn0veG1sL3twcm90b2NvbH1fe3BvcnR9X3ZuY19ubWFwLnhtbCIge2FkZHJlc3N9JykK',
            '_mssql_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLChtcy1zcWwqIG9yIHNzbCopIGFuZCBub3QgKGJydXRlIG9yIGJyb2FkY2FzdCBvciBkb3Mgb3IgZXh0ZXJuYWwgb3IgZnV6emVyKSIgLS1zY3JpcHQtYXJncz0ibXNzcWwuaW5zdGFuY2UtcG9ydD17cG9ydH0sbXNzcWwudXNlcm5hbWU9c2EsbXNzcWwucGFzc3dvcmQ9c2EiIC1vTiAie3NjYW5kaXJ9L3twcm90b2NvbH1fe3BvcnR9X21zc3FsX25tYXAudHh0IiAtb1ggIntzY2FuZGlyfS94bWwve3Byb3RvY29sfV97cG9ydH1fbXNzcWxfbm1hcC54bWwiIHthZGRyZXNzfScpCg==',
            '_mongodb_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLChtb25nb2RiKiBvciBzc2wqKSBhbmQgbm90IChicnV0ZSBvciBicm9hZGNhc3Qgb3IgZG9zIG9yIGV4dGVybmFsIG9yIGZ1enplcikiIC1vTiAie3NjYW5kaXJ9L3twcm90b2NvbH1fe3BvcnR9X21vbmdvZGJfbm1hcC50eHQiIC1vWCAie3NjYW5kaXJ9L3htbC97cHJvdG9jb2x9X3twb3J0fV9tb25nb2RiX25tYXAueG1sIiB7YWRkcmVzc30nKQo=',
            '_curl.html': 'Y3VybCAtc1NpayB7aHR0cF9zY2hlbWV9Oi8ve2FkZHJlc3N2Nn06e3BvcnR9JyArIHNlbGYuZ2V0X29wdGlvbigncGF0aCcpLCBvdXRmaWxlPSd7cHJvdG9jb2x9X3twb3J0fV97aHR0cF9zY2hlbWV9X2N1cmwuaHRtbCcpCg==',
            '_telnet-nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLHRlbG5ldC1lbmNyeXB0aW9uLHRlbG5ldC1udGxtLWluZm8iIC1vTiAie3NjYW5kaXJ9L3twcm90b2NvbH1fe3BvcnR9X3RlbG5ldC1ubWFwLnR4dCIgLW9YICJ7c2NhbmRpcn0veG1sL3twcm90b2NvbH1fe3BvcnR9X3RlbG5ldF9ubWFwLnhtbCIge2FkZHJlc3N9JykK',
            '_smb_vulnerabilities.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0ic21iLXZ1bG4tKiIgLS1zY3JpcHQtYXJncz0idW5zYWZlPTEiIC1vTiAie3NjYW5kaXJ9L3twcm90b2NvbH1fe3BvcnR9X3NtYl92dWxuZXJhYmlsaXRpZXMudHh0IiAtb1ggIntzY2FuZGlyfS94bWwve3Byb3RvY29sfV97cG9ydH1fc21iX3Z1bG5lcmFiaWxpdGllcy54bWwiIHthZGRyZXNzfScpCg==',
            'smbclient.txt': 'c21iY2xpZW50IC1MIC8ve2FkZHJlc3N9IC1OIC1JIHthZGRyZXNzfSAyPiYxJywgb3V0ZmlsZT0nc21iY2xpZW50LnR4dCcpCg==',
            '_mountd_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLG5mcyogYW5kIG5vdCAoYnJ1dGUgb3IgYnJvYWRjYXN0IG9yIGRvcyBvciBleHRlcm5hbCBvciBmdXp6ZXIpIiAtb04gIntzY2FuZGlyfS97cHJvdG9jb2x9X3twb3J0fV9tb3VudGRfbm1hcC50eHQiIC1vWCAie3NjYW5kaXJ9L3htbC97cHJvdG9jb2x9X3twb3J0fV9tb3VudGRfbm1hcC54bWwiIHthZGRyZXNzfScpCg==',
            '_ntp_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLChudHAqIG9yIHNzbCopIGFuZCBub3QgKGJydXRlIG9yIGJyb2FkY2FzdCBvciBkb3Mgb3IgZXh0ZXJuYWwgb3IgZnV6emVyKSIgLW9OICJ7c2NhbmRpcn0ve3Byb3RvY29sfV97cG9ydH1fbnRwX25tYXAudHh0IiAtb1ggIntzY2FuZGlyfS94bWwve3Byb3RvY29sfV97cG9ydH1fbnRwX25tYXAueG1sIiB7YWRkcmVzc30nKQo=',
            '_tftp-nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLHRmdHAtZW51bSIgLW9OICJ7c2NhbmRpcn0ve3Byb3RvY29sfV97cG9ydH1fdGZ0cC1ubWFwLnR4dCIgLW9YICJ7c2NhbmRpcn0veG1sL3twcm90b2NvbH1fe3BvcnR9X3RmdHBfbm1hcC54bWwiIHthZGRyZXNzfScpCg==',
            '_ldap_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLChsZGFwKiBvciBzc2wqKSBhbmQgbm90IChicnV0ZSBvciBicm9hZGNhc3Qgb3IgZG9zIG9yIGV4dGVybmFsIG9yIGZ1enplcikiIC1vTiAie3NjYW5kaXJ9L3twcm90b2NvbH1fe3BvcnR9X2xkYXBfbm1hcC50eHQiIC1vWCAie3NjYW5kaXJ9L3htbC97cHJvdG9jb2x9X3twb3J0fV9sZGFwX25tYXAueG1sIiB7YWRkcmVzc30nKQo=',
            '_showmount.txt': 'c2hvd21vdW50IC1lIHthZGRyZXNzfSAyPiYxJywgb3V0ZmlsZT0ne3Byb3RvY29sfV97cG9ydH1fc2hvd21vdW50LnR4dCcpCg==',
            '_nikto.txt': 'bmlrdG8gLWFzaz1ubyAtVHVuaW5nPXg0NTY3ODkwYWMgLW5vaW50ZXJhY3RpdmUgLWhvc3Qge2h0dHBfc2NoZW1lfTovL3thZGRyZXNzfTp7cG9ydH0gMj4mMSB8IHRlZSAie3NjYW5kaXJ9L3twcm90b2NvbH1fe3BvcnR9X3todHRwX3NjaGVtZX1fbmlrdG8udHh0IicpCg==',
            '_ftp_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLChmdHAqIG9yIHNzbCopIGFuZCBub3QgKGJydXRlIG9yIGJyb2FkY2FzdCBvciBkb3Mgb3IgZXh0ZXJuYWwgb3IgZnV6emVyKSIgLW9OICJ7c2NhbmRpcn0ve3Byb3RvY29sfV97cG9ydH1fZnRwX25tYXAudHh0IiAtb1ggIntzY2FuZGlyfS94bWwve3Byb3RvY29sfV97cG9ydH1fZnRwX25tYXAueG1sIiB7YWRkcmVzc30nKQo=',
            '_redis_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLHJlZGlzLWluZm8iIC1vTiAie3NjYW5kaXJ9L3twcm90b2NvbH1fe3BvcnR9X3JlZGlzX25tYXAudHh0IiAtb1ggIntzY2FuZGlyfS94bWwve3Byb3RvY29sfV97cG9ydH1fcmVkaXNfbm1hcC54bWwiIHthZGRyZXNzfScpCg==',
            '_snmp_snmpwalk.txt': 'c25tcHdhbGsgLWMgcHVibGljIC12IDEge2FkZHJlc3N9IDI+JjEnLCBvdXRmaWxlPSd7cHJvdG9jb2x9X3twb3J0fV9zbm1wX3NubXB3YWxrLnR4dCcpCg==',
            '_snmp_snmpwalk_system_processes.txt': 'c25tcHdhbGsgLWMgcHVibGljIC12IDEge2FkZHJlc3N9IDEuMy42LjEuMi4xLjI1LjEuNi4wIDI+JjEnLCBvdXRmaWxlPSd7cHJvdG9jb2x9X3twb3J0fV9zbm1wX3NubXB3YWxrX3N5c3RlbV9wcm9jZXNzZXMudHh0JykK',
            '_snmp_snmpwalk_running_processes.txt': 'c25tcHdhbGsgLWMgcHVibGljIC12IDEge2FkZHJlc3N9IDEuMy42LjEuMi4xLjI1LjQuMi4xLjIgMj4mMScsIG91dGZpbGU9J3tzY2FuZGlyfS97cHJvdG9jb2x9X3twb3J0fV9zbm1wX3NubXB3YWxrX3J1bm5pbmdfcHJvY2Vzc2VzLnR4dCcpCg==',
            '_snmp_snmpwalk_process_paths.txt': 'c25tcHdhbGsgLWMgcHVibGljIC12IDEge2FkZHJlc3N9IDEuMy42LjEuMi4xLjI1LjQuMi4xLjQgMj4mMScsIG91dGZpbGU9J3twcm90b2NvbH1fe3BvcnR9X3NubXBfc25tcHdhbGtfcHJvY2Vzc19wYXRocy50eHQnKQo=',
            '_snmp_snmpwalk_storage_units.txt': 'c25tcHdhbGsgLWMgcHVibGljIC12IDEge2FkZHJlc3N9IDEuMy42LjEuMi4xLjI1LjIuMy4xLjQgMj4mMScsIG91dGZpbGU9J3twcm90b2NvbH1fe3BvcnR9X3NubXBfc25tcHdhbGtfc3RvcmFnZV91bml0cy50eHQnKQo=',
            '_snmp_snmpwalk_software_names.txt': 'c25tcHdhbGsgLWMgcHVibGljIC12IDEge2FkZHJlc3N9IDEuMy42LjEuMi4xLjI1LjIuMy4xLjQgMj4mMScsIG91dGZpbGU9J3twcm90b2NvbH1fe3BvcnR9X3NubXBfc25tcHdhbGtfc29mdHdhcmVfbmFtZXMudHh0JykK',
            '_snmp_snmpwalk_user_accounts.txt': 'c25tcHdhbGsgLWMgcHVibGljIC12IDEge2FkZHJlc3N9IDEuMy42LjEuNC4xLjc3LjEuMi4yNSAyPiYxJywgb3V0ZmlsZT0ne3Byb3RvY29sfV97cG9ydH1fc25tcF9zbm1wd2Fsa191c2VyX2FjY291bnRzLnR4dCcpCg==',
            '_snmp_snmpwalk_tcp_ports.txt': 'c25tcHdhbGsgLWMgcHVibGljIC12IDEge2FkZHJlc3N9IDEuMy42LjEuMi4xLjYuMTMuMS4zIDI+JjEnLCBvdXRmaWxlPSd7cHJvdG9jb2x9X3twb3J0fV9zbm1wX3NubXB3YWxrX3RjcF9wb3J0cy50eHQnKQo=',
            '_rpc_rpcdump.txt': 'aW1wYWNrZXQtcnBjZHVtcCAtcG9ydCB7cG9ydH0ge2FkZHJlc3N9Jywgb3V0ZmlsZT0ne3Byb3RvY29sfV97cG9ydH1fcnBjX3JwY2R1bXAudHh0JykK',
            '_smtp_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLChzbXRwKiBvciBzc2wqKSBhbmQgbm90IChicnV0ZSBvciBicm9hZGNhc3Qgb3IgZG9zIG9yIGV4dGVybmFsIG9yIGZ1enplcikiIC1vTiAie3NjYW5kaXJ9L3twcm90b2NvbH1fe3BvcnR9X3NtdHBfbm1hcC50eHQiIC1vWCAie3NjYW5kaXJ9L3htbC97cHJvdG9jb2x9X3twb3J0fV9zbXRwX25tYXAueG1sIiB7YWRkcmVzc30nKQo=',
            '_snmp-nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLChzbm1wKiBvciBzc2wqKSBhbmQgbm90IChicnV0ZSBvciBicm9hZGNhc3Qgb3IgZG9zIG9yIGV4dGVybmFsIG9yIGZ1enplcikiIC1vTiAie3NjYW5kaXJ9L3twcm90b2NvbH1fe3BvcnR9X3NubXAtbm1hcC50eHQiIC1vWCAie3NjYW5kaXJ9L3htbC97cHJvdG9jb2x9X3twb3J0fV9zbm1wX25tYXAueG1sIiB7YWRkcmVzc30nKQo=',
            '_nntp_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLG5udHAtbnRsbS1pbmZvIiAtb04gIntzY2FuZGlyfS97cHJvdG9jb2x9X3twb3J0fV9ubnRwX25tYXAudHh0IiAtb1ggIntzY2FuZGlyfS94bWwve3Byb3RvY29sfV97cG9ydH1fbm50cF9ubWFwLnhtbCIge2FkZHJlc3N9JykK',
            '_whatweb.txt': 'd2hhdHdlYiAtLWNvbG9yPW5ldmVyIC0tbm8tZXJyb3JzIC1hIDMgLXYge2h0dHBfc2NoZW1lfTovL3thZGRyZXNzfTp7cG9ydH0gMj4mMScsIG91dGZpbGU9J3twcm90b2NvbH1fe3BvcnR9X3todHRwX3NjaGVtZX1fd2hhdHdlYi50eHQnKQo=',
            '_smb_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLChuYnN0YXQgb3Igc21iKiBvciBzc2wqKSBhbmQgbm90IChicnV0ZSBvciBicm9hZGNhc3Qgb3IgZG9zIG9yIGV4dGVybmFsIG9yIGZ1enplcikiIC1vTiAie3NjYW5kaXJ9L3twcm90b2NvbH1fe3BvcnR9X3NtYl9ubWFwLnR4dCIgLW9YICJ7c2NhbmRpcn0veG1sL3twcm90b2NvbH1fe3BvcnR9X3NtYl9ubWFwLnhtbCIge2FkZHJlc3N9JykK',
            '_dns_reverse-lookup.txt': 'ZGlnIC1wIHtwb3J0fSAteCB7YWRkcmVzc30gQHthZGRyZXNzfScsIG91dGZpbGU9J3twcm90b2NvbH1fe3BvcnR9X2Ruc19yZXZlcnNlLWxvb2t1cC50eHQnKQo=',
            '_oracle_scanner.txt': 'b3NjYW5uZXIgLXYgLXMge2FkZHJlc3N9IC1QIHtwb3J0fSAyPiYxJywgb3V0ZmlsZT0ne3Byb3RvY29sfV97cG9ydH1fb3JhY2xlX3NjYW5uZXIudHh0JykK',
            '_subdomains_': 'Z29idXN0ZXIgZG5zIC1kICcgKyBkb21haW4gKyAnIC1yIHthZGRyZXNzdjZ9IC13ICcgKyB3b3JkbGlzdCArICcgLW8gIntzY2FuZGlyfS97cHJvdG9jb2x9X3twb3J0fV8nICsgZG9tYWluICsgJ19zdWJkb21haW5zXycgKyBuYW1lICsgJy50eHQiJykK',
            '_screenshot.png': 'd2todG1sdG9pbWFnZSAtLWZvcm1hdCBwbmcge2h0dHBfc2NoZW1lfTovL3thZGRyZXNzdjZ9Ontwb3J0fS8ge3NjYW5kaXJ9L3twcm90b2NvbH1fe3BvcnR9X3todHRwX3NjaGVtZX1fc2NyZWVuc2hvdC5wbmcnKQo=',
            '_rdp_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLChyZHAqIG9yIHNzbCopIGFuZCBub3QgKGJydXRlIG9yIGJyb2FkY2FzdCBvciBkb3Mgb3IgZXh0ZXJuYWwgb3IgZnV6emVyKSIgLW9OICJ7c2NhbmRpcn0ve3Byb3RvY29sfV97cG9ydH1fcmRwX25tYXAudHh0IiAtb1ggIntzY2FuZGlyfS94bWwve3Byb3RvY29sfV97cG9ydH1fcmRwX25tYXAueG1sIiB7YWRkcmVzc30nKQo=',
            'nbtscan.txt': 'bmJ0c2NhbiAtcnZoIHtpcGFkZHJlc3N9IDI+JjEnLCBvdXRmaWxlPSduYnRzY2FuLnR4dCcpCg==',
            '_known-security.txt': 'Y3VybCAtc1Npa2Yge2h0dHBfc2NoZW1lfTovL3thZGRyZXNzdjZ9Ontwb3J0fS8ud2VsbC1rbm93bi9zZWN1cml0eS50eHQnLCBmdXR1cmVfb3V0ZmlsZT0ne3Byb3RvY29sfV97cG9ydH1fe2h0dHBfc2NoZW1lfV9rbm93bi1zZWN1cml0eS50eHQnKQo=',
            '_rsync_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLChyc3luYyogb3Igc3NsKikgYW5kIG5vdCAoYnJ1dGUgb3IgYnJvYWRjYXN0IG9yIGRvcyBvciBleHRlcm5hbCBvciBmdXp6ZXIpIiAtb04gIntzY2FuZGlyfS97cHJvdG9jb2x9X3twb3J0fV9yc3luY19ubWFwLnR4dCIgLW9YICJ7c2NhbmRpcn0veG1sL3twcm90b2NvbH1fe3BvcnR9X3JzeW5jX25tYXAueG1sIiB7YWRkcmVzc30nKQo=',
            '_imap_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLChpbWFwKiBvciBzc2wqKSBhbmQgbm90IChicnV0ZSBvciBicm9hZGNhc3Qgb3IgZG9zIG9yIGV4dGVybmFsIG9yIGZ1enplcikiIC1vTiAie3NjYW5kaXJ9L3twcm90b2NvbH1fe3BvcnR9X2ltYXBfbm1hcC50eHQiIC1vWCAie3NjYW5kaXJ9L3htbC97cHJvdG9jb2x9X3twb3J0fV9pbWFwX25tYXAueG1sIiB7YWRkcmVzc30nKQo=',
            '_sip_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLHNpcC1lbnVtLXVzZXJzLHNpcC1tZXRob2RzIiAtb04gIntzY2FuZGlyfS97cHJvdG9jb2x9X3twb3J0fV9zaXBfbm1hcC50eHQiIC1vWCAie3NjYW5kaXJ9L3htbC97cHJvdG9jb2x9X3twb3J0fV9zaXBfbm1hcC54bWwiIHthZGRyZXNzfScpCg==',
            '_vhosts_': 'ZmZ1ZiAtdSB7aHR0cF9zY2hlbWV9Oi8vJyArIGhvc3RuYW1lICsgJzp7cG9ydH0vIC10ICcgKyBzdHIoc2VsZi5nZXRfb3B0aW9uKCd0aHJlYWRzJykpICsgJyAtdyAnICsgd29yZGxpc3QgKyAnIC1IICJIb3N0OiBGVVpaLicgKyBob3N0bmFtZSArICciIC1tYyBhbGwgLWZzICcgKyBzaXplICsgJyAtciAtbm9uaW50ZXJhY3RpdmUgLXMgfCB0ZWUgIntzY2FuZGlyfS97cHJvdG9jb2x9X3twb3J0fV97aHR0cF9zY2hlbWV9XycgKyBob3N0bmFtZSArICdfdmhvc3RzXycgKyBuYW1lICsgJy50eHQiJykK',
            '_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLChodHRwKiBvciBzc2wqKSBhbmQgbm90IChicnV0ZSBvciBicm9hZGNhc3Qgb3IgZG9zIG9yIGV4dGVybmFsIG9yIGh0dHAtc2xvd2xvcmlzKiBvciBmdXp6ZXIpIiAtb04gIntzY2FuZGlyfS97cHJvdG9jb2x9X3twb3J0fV97aHR0cF9zY2hlbWV9X25tYXAudHh0IiAtb1ggIntzY2FuZGlyfS94bWwve3Byb3RvY29sfV97cG9ydH1fe2h0dHBfc2NoZW1lfV9ubWFwLnhtbCIge2FkZHJlc3N9JykK',
            '_finger_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLGZpbmdlciIgLW9OICJ7c2NhbmRpcn0ve3Byb3RvY29sfV97cG9ydH1fZmluZ2VyX25tYXAudHh0IiAtb1ggIntzY2FuZGlyfS94bWwve3Byb3RvY29sfV97cG9ydH1fZmluZ2VyX25tYXAueG1sIiB7YWRkcmVzc30nKQo=',
            '_dns_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLChkbnMqIG9yIHNzbCopIGFuZCBub3QgKGJydXRlIG9yIGJyb2FkY2FzdCBvciBkb3Mgb3IgZXh0ZXJuYWwgb3IgZnV6emVyKSIgLW9OICJ7c2NhbmRpcn0ve3Byb3RvY29sfV97cG9ydH1fZG5zX25tYXAudHh0IiAtb1ggIntzY2FuZGlyfS94bWwve3Byb3RvY29sfV97cG9ydH1fZG5zX25tYXAueG1sIiB7YWRkcmVzc30nKQo=',
            '_feroxbuster_': 'ZmVyb3hidXN0ZXIgLXUge2h0dHBfc2NoZW1lfTovL3thZGRyZXNzdjZ9Ontwb3J0fS8gLXQgJyArIHN0cihzZWxmLmdldF9vcHRpb24oJ3RocmVhZHMnKSkgKyAnIC13ICcgKyB3b3JkbGlzdCArICcgLXggIicgKyBzZWxmLmdldF9vcHRpb24oJ2V4dCcpICsgJyIgLXYgLWsgJyArICgnJyBpZiBzZWxmLmdldF9vcHRpb24oJ3JlY3Vyc2l2ZScpIGVsc2UgJy1uICcpICArICctcSAtZSAtciAtbyAie3NjYW5kaXJ9L3twcm90b2NvbH1fe3BvcnR9X3todHRwX3NjaGVtZX1fZmVyb3hidXN0ZXJfJyArIG5hbWUgKyAnLnR4dCInICsgKCcgJyArIHNlbGYuZ2V0X29wdGlvbignZXh0cmFzJykgaWYgc2VsZi5nZXRfb3B0aW9uKCdleHRyYXMnKSBlbHNlICcnKSkK',
            '_gobuster_': 'Z29idXN0ZXIgZGlyIC11IHtodHRwX3NjaGVtZX06Ly97YWRkcmVzc3Y2fTp7cG9ydH0vIC10ICcgKyBzdHIoc2VsZi5nZXRfb3B0aW9uKCd0aHJlYWRzJykpICsgJyAtdyAnICsgd29yZGxpc3QgKyAnIC1lIC1rIC14ICInICsgc2VsZi5nZXRfb3B0aW9uKCdleHQnKSArICciIC16IC1yIC1vICJ7c2NhbmRpcn0ve3Byb3RvY29sfV97cG9ydH1fe2h0dHBfc2NoZW1lfV9nb2J1c3Rlcl8nICsgbmFtZSArICcudHh0IicgKyAoJyAnICsgc2VsZi5nZXRfb3B0aW9uKCdleHRyYXMnKSBpZiBzZWxmLmdldF9vcHRpb24oJ2V4dHJhcycpIGVsc2UgJycpKQo=',
            '_dirsearch_': 'ZGlyc2VhcmNoIC11IHtodHRwX3NjaGVtZX06Ly97YWRkcmVzc306e3BvcnR9LyAtdCAnICsgc3RyKHNlbGYuZ2V0X29wdGlvbigndGhyZWFkcycpKSArICcgLWUgIicgKyBzZWxmLmdldF9vcHRpb24oJ2V4dCcpICsgJyIgLWYgLXEgLUYgJyArICgnLXIgJyBpZiBzZWxmLmdldF9vcHRpb24oJ3JlY3Vyc2l2ZScpIGVsc2UgJycpICsgJy13ICcgKyB3b3JkbGlzdCArICcgLS1mb3JtYXQ9cGxhaW4gLW8gIntzY2FuZGlyfS97cHJvdG9jb2x9X3twb3J0fV97aHR0cF9zY2hlbWV9X2RpcnNlYXJjaF8nICsgbmFtZSArICcudHh0IicgKyAoJyAnICsgc2VsZi5nZXRfb3B0aW9uKCdleHRyYXMnKSBpZiBzZWxmLmdldF9vcHRpb24oJ2V4dHJhcycpIGVsc2UgJycpKQo=',
            '_ffuf_': 'ZmZ1ZiAtdSB7aHR0cF9zY2hlbWV9Oi8ve2FkZHJlc3N2Nn06e3BvcnR9L0ZVWlogLXQgJyArIHN0cihzZWxmLmdldF9vcHRpb24oJ3RocmVhZHMnKSkgKyAnIC13ICcgKyB3b3JkbGlzdCArICcgLWUgIicgKyBkb3RfZXh0ZW5zaW9ucyArICciIC12IC1yICcgKyAoJy1yZWN1cnNpb24gJyBpZiBzZWxmLmdldF9vcHRpb24oJ3JlY3Vyc2l2ZScpIGVsc2UgJycpICsgJy1ub25pbnRlcmFjdGl2ZScgKyAoJyAnICsgc2VsZi5nZXRfb3B0aW9uKCdleHRyYXMnKSBpZiBzZWxmLmdldF9vcHRpb24oJ2V4dHJhcycpIGVsc2UgJycpICsgJyB8IHRlZSB7c2NhbmRpcn0ve3Byb3RvY29sfV97cG9ydH1fe2h0dHBfc2NoZW1lfV9mZnVmXycgKyBuYW1lICsgJy50eHQnKQo=',
            '_dirb_': 'ZGlyYiB7aHR0cF9zY2hlbWV9Oi8ve2FkZHJlc3N2Nn06e3BvcnR9LyAnICsgd29yZGxpc3QgKyAnIC1sICcgKyAoJycgaWYgc2VsZi5nZXRfb3B0aW9uKCdyZWN1cnNpdmUnKSBlbHNlICctciAnKSAgKyAnLVMgLVggIiwnICsgZG90X2V4dGVuc2lvbnMgKyAnIiAtZiAtbyAie3NjYW5kaXJ9L3twcm90b2NvbH1fe3BvcnR9X3todHRwX3NjaGVtZX1fZGlyYl8nICsgbmFtZSArICcudHh0IicgKyAoJyAnICsgc2VsZi5nZXRfb3B0aW9uKCdleHRyYXMnKSBpZiBzZWxmLmdldF9vcHRpb24oJ2V4dHJhcycpIGVsc2UgJycpKQo=',
            '_cassandra_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLChjYXNzYW5kcmEqIG9yIHNzbCopIGFuZCBub3QgKGJydXRlIG9yIGJyb2FkY2FzdCBvciBkb3Mgb3IgZXh0ZXJuYWwgb3IgZnV6emVyKSIgLW9OICJ7c2NhbmRpcn0ve3Byb3RvY29sfV97cG9ydH1fY2Fzc2FuZHJhX25tYXAudHh0IiAtb1ggIntzY2FuZGlyfS94bWwve3Byb3RvY29sfV97cG9ydH1fY2Fzc2FuZHJhX25tYXAueG1sIiB7YWRkcmVzc30nKQo=',
            '_curl-robots.txt': 'Y3VybCAtc1Npa2Yge2h0dHBfc2NoZW1lfTovL3thZGRyZXNzdjZ9Ontwb3J0fS9yb2JvdHMudHh0JywgZnV0dXJlX291dGZpbGU9J3twcm90b2NvbH1fe3BvcnR9X3todHRwX3NjaGVtZX1fY3VybC1yb2JvdHMudHh0JykK',
            '_nfs_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLChycGNpbmZvIG9yIG5mcyopIGFuZCBub3QgKGJydXRlIG9yIGJyb2FkY2FzdCBvciBkb3Mgb3IgZXh0ZXJuYWwgb3IgZnV6emVyKSIgLW9OICJ7c2NhbmRpcn0ve3Byb3RvY29sfV97cG9ydH1fbmZzX25tYXAudHh0IiAtb1ggIntzY2FuZGlyfS94bWwve3Byb3RvY29sfV97cG9ydH1fbmZzX25tYXAueG1sIiB7YWRkcmVzc30nKQo=',
            '_multicastdns_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLChkbnMqIG9yIHNzbCopIGFuZCBub3QgKGJydXRlIG9yIGJyb2FkY2FzdCBvciBkb3Mgb3IgZXh0ZXJuYWwgb3IgZnV6emVyKSIgLW9OICJ7c2NhbmRpcn0ve3Byb3RvY29sfV97cG9ydH1fbXVsdGljYXN0ZG5zX25tYXAudHh0IiAtb1ggIntzY2FuZGlyfS94bWwve3Byb3RvY29sfV97cG9ydH1fbXVsdGljYXN0ZG5zX25tYXAueG1sIiB7YWRkcmVzc30nKQo=',
            '_cups_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLChjdXBzKiBvciBzc2wqKSBhbmQgbm90IChicnV0ZSBvciBicm9hZGNhc3Qgb3IgZG9zIG9yIGV4dGVybmFsIG9yIGZ1enplcikiIC1vTiAie3NjYW5kaXJ9L3twcm90b2NvbH1fe3BvcnR9X2N1cHNfbm1hcC50eHQiIC1vWCAie3NjYW5kaXJ9L3htbC97cHJvdG9jb2x9X3twb3J0fV9jdXBzX25tYXAueG1sIiB7YWRkcmVzc30nKQo=',
            '_irc_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC0tc2NyaXB0IGlyYy1ib3RuZXQtY2hhbm5lbHMsaXJjLWluZm8saXJjLXVucmVhbGlyY2QtYmFja2Rvb3IgLW9OICJ7c2NhbmRpcn0ve3Byb3RvY29sfV97cG9ydH1faXJjX25tYXAudHh0IiAtb1ggIntzY2FuZGlyfS94bWwve3Byb3RvY29sfV97cG9ydH1faXJjX25tYXAueG1sIiAtcCB7cG9ydH0ge2FkZHJlc3N9JykK',
            '_distcc_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLGRpc3RjYy1jdmUyMDA0LTI2ODciIC0tc2NyaXB0LWFyZ3M9ImRpc3RjYy1jdmUyMDA0LTI2ODcuY21kPWlkIiAtb04gIntzY2FuZGlyfS97cHJvdG9jb2x9X3twb3J0fV9kaXN0Y2Nfbm1hcC50eHQiIC1vWCAie3NjYW5kaXJ9L3htbC97cHJvdG9jb2x9X3twb3J0fV9kaXN0Y2Nfbm1hcC54bWwiIHthZGRyZXNzfScpCg==',
            '_ajp_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLChhanAtKiBvciBzc2wqKSBhbmQgbm90IChicnV0ZSBvciBicm9hZGNhc3Qgb3IgZG9zIG9yIGV4dGVybmFsIG9yIGZ1enplcikiIC1vTiAie3NjYW5kaXJ9L3twcm90b2NvbH1fe3BvcnR9X2FqcF9ubWFwLnR4dCIgLW9YICJ7c2NhbmRpcn0veG1sL3twcm90b2NvbH1fe3BvcnR9X2FqcF9ubWFwLnhtbCIge2FkZHJlc3N9JykK',
            'smbmap-share-permissions.txt': 'c21ibWFwIC1IIHthZGRyZXNzfSAtUCB7cG9ydH0gMj4mMScsIG91dGZpbGU9J3NtYm1hcC1zaGFyZS1wZXJtaXNzaW9ucy50eHQnKQo=',
            'smbmap-share-permissions.txt': 'c21ibWFwIC11IG51bGwgLXAgIiIgLUgge2FkZHJlc3N9IC1QIHtwb3J0fSAyPiYxJywgb3V0ZmlsZT0nc21ibWFwLXNoYXJlLXBlcm1pc3Npb25zLnR4dCcpCg==',
            'smbmap-list-contents.txt': 'c21ibWFwIC1IIHthZGRyZXNzfSAtUCB7cG9ydH0gLXIgMj4mMScsIG91dGZpbGU9J3NtYm1hcC1saXN0LWNvbnRlbnRzLnR4dCcpCg==',
            'smbmap-list-contents.txt': 'c21ibWFwIC11IG51bGwgLXAgIiIgLUgge2FkZHJlc3N9IC1QIHtwb3J0fSAtciAyPiYxJywgb3V0ZmlsZT0nc21ibWFwLWxpc3QtY29udGVudHMudHh0JykK',
            'smbmap-execute-command.txt': 'c21ibWFwIC1IIHthZGRyZXNzfSAtUCB7cG9ydH0gLXggImlwY29uZmlnIC9hbGwiIDI+JjEnLCBvdXRmaWxlPSdzbWJtYXAtZXhlY3V0ZS1jb21tYW5kLnR4dCcpCg==',
            'smbmap-execute-command.txt': 'c21ibWFwIC11IG51bGwgLXAgIiIgLUgge2FkZHJlc3N9IC1QIHtwb3J0fSAteCAiaXBjb25maWcgL2FsbCIgMj4mMScsIG91dGZpbGU9J3NtYm1hcC1leGVjdXRlLWNvbW1hbmQudHh0JykK',
            '_kerberos_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLGtyYjUtZW51bS11c2VycyIgLS1zY3JpcHQtYXJncyBrcmI1LWVudW0tdXNlcnMucmVhbG09IicgKyBzZWxmLmdldF9nbG9iYWwoJ2RvbWFpbicpICsgJyIsdXNlcmRiPSInICsgc2VsZi5nZXRfZ2xvYmFsKCd1c2VybmFtZS13b3JkbGlzdCcpICsgJyIgLW9OICJ7c2NhbmRpcn0ve3Byb3RvY29sfV97cG9ydH1fa2VyYmVyb3Nfbm1hcC50eHQiIC1vWCAie3NjYW5kaXJ9L3htbC97cHJvdG9jb2x9X3twb3J0fV9rZXJiZXJvc19ubWFwLnhtbCIge2FkZHJlc3N9JykK',
            '_kerberos_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLGtyYjUtZW51bS11c2VycyIgLW9OICJ7c2NhbmRpcn0ve3Byb3RvY29sfV97cG9ydH1fa2VyYmVyb3Nfbm1hcC50eHQiIC1vWCAie3NjYW5kaXJ9L3htbC97cHJvdG9jb2x9X3twb3J0fV9rZXJiZXJvc19ubWFwLnhtbCIge2FkZHJlc3N9JykK',
            '_dnsrecon_default.txt': 'ZG5zcmVjb24gLW4ge2FkZHJlc3N9IC1kICcgKyBzZWxmLmdldF9nbG9iYWwoJ2RvbWFpbicpICsgJyAyPiYxJywgb3V0ZmlsZT0ne3Byb3RvY29sfV97cG9ydH1fZG5zcmVjb25fZGVmYXVsdC50eHQnKQo=',
            '_ssh_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLHNzaDItZW51bS1hbGdvcyxzc2gtaG9zdGtleSxzc2gtYXV0aC1tZXRob2RzIiAtb04gIntzY2FuZGlyfS97cHJvdG9jb2x9X3twb3J0fV9zc2hfbm1hcC50eHQiIC1vWCAie3NjYW5kaXJ9L3htbC97cHJvdG9jb2x9X3twb3J0fV9zc2hfbm1hcC54bWwiIHthZGRyZXNzfScpCg==',
            '_sslscan.html': 'c3Nsc2NhbiAtLXNob3ctY2VydGlmaWNhdGUgLS1uby1jb2xvdXIge2FkZHJlc3N2Nn06e3BvcnR9IDI+JjEnLCBvdXRmaWxlPSd7cHJvdG9jb2x9X3twb3J0fV9zc2xzY2FuLmh0bWwnKQo=',
            '_rpc_architecture.txt': 'aW1wYWNrZXQtZ2V0QXJjaCAtdGFyZ2V0IHthZGRyZXNzfScsIG91dGZpbGU9J3twcm90b2NvbH1fe3BvcnR9X3JwY19hcmNoaXRlY3R1cmUudHh0JykK',
            '_snmp_onesixtyone.txt': 'b25lc2l4dHlvbmUgLWMgJyArIHNlbGYuZ2V0X29wdGlvbignY29tbXVuaXR5LXN0cmluZ3MnKSArICcgLWRkIHthZGRyZXNzfSAyPiYxJywgb3V0ZmlsZT0ne3Byb3RvY29sfV97cG9ydH1fc25tcF9vbmVzaXh0eW9uZS50eHQnKQo=',
            '_rmi_nmap.txt': 'bm1hcCB7bm1hcF9leHRyYX0gLXNWIC1wIHtwb3J0fSAtLXNjcmlwdD0iYmFubmVyLHJtaS12dWxuLWNsYXNzbG9hZGVyLHJtaS1kdW1wcmVnaXN0cnkiIC1vTiAie3NjYW5kaXJ9L3twcm90b2NvbH1fe3BvcnR9X3JtaV9ubWFwLnR4dCIgLW9YICJ7c2NhbmRpcn0veG1sL3twcm90b2NvbH1fe3BvcnR9X3JtaV9ubWFwLnhtbCIge2FkZHJlc3N9JykK'
        }
        for command in command_grep.keys():
            if command in report_file.name:
                return command_grep[command]
        return "Unknown"

    def _get_tool_used(self, report_file):

        tool_grep = {
            '_smtp_user-enum_hydra_vrfy.txt': 'hydra',
            '_smtp_user-enum_hydra_expn.txt': 'hydra',
            '_mysql_nmap.txt': 'nmap',
            'enum4linux.txt': 'enum4linux',
            'enum4linux-ng.txt': 'enum4linux',
            '_oracle_nmap.txt': 'nmap',
            '_rpc_nmap.txt': 'nmap',
            '_pop3_nmap.txt': 'nmap',
            '_dns_zone-transfer-domain.txt': 'dig',
            '_dns_zone-transfer-hostname.txt': 'dig',
            '_dns_zone-transfer.txt': 'dig',
            '_oracle_tnscmd_ping.txt': 'tnscmd10g',
            '_oracle_tnscmd_version.txt': 'tnscmd10g',
            '_redis_info.txt': 'redis-cli',
            '_redis_config.txt': 'redis-cli',
            '_redis_client-list.txt': 'redis-cli',
            '_rsync_file_list.txt': 'rsync',
            '_vnc_nmap.txt': 'nmap',
            '_mssql_nmap.txt': 'nmap',
            '_mongodb_nmap.txt': 'nmap',
            '_curl.html': 'curl',
            '_telnet-nmap.txt': 'nmap',
            '_smb_vulnerabilities.txt': 'nmap',
            'smbclient.txt': 'smbclient',
            '_mountd_nmap.txt': 'nmap',
            '_ntp_nmap.txt': 'nmap',
            '_tftp-nmap.txt': 'nmap',
            '_ldap_nmap.txt': 'nmap',
            '_showmount.txt': 'showmount',
            '_nikto.txt': 'nikto',
            '_ftp_nmap.txt': 'nmap',
            '_redis_nmap.txt': 'nmap',
            '_snmp_snmpwalk.txt': 'snmpwalk',
            '_snmp_snmpwalk_system_processes.txt': 'snmpwalk',
            '_snmp_snmpwalk_running_processes.txt': 'snmpwalk',
            '_snmp_snmpwalk_process_paths.txt': 'snmpwalk',
            '_snmp_snmpwalk_storage_units.txt': 'snmpwalk',
            '_snmp_snmpwalk_software_names.txt': 'snmpwalk',
            '_snmp_snmpwalk_user_accounts.txt': 'snmpwalk',
            '_snmp_snmpwalk_tcp_ports.txt': 'snmpwalk',
            '_rpc_rpcdump.txt': 'rpcdump',
            '_smtp_nmap.txt': 'nmap',
            '_snmp-nmap.txt': 'nmap',
            '_nntp_nmap.txt': 'nmap',
            '_whatweb.txt': 'whatweb',
            '_smb_nmap.txt': 'nmap',
            '_dns_reverse-lookup.txt': 'dig',
            '_oracle_scanner.txt': 'oscanner',
            '_subdomains_': 'gobuster',
            '_screenshot.png': 'wkhtmltoimage',
            '_rdp_nmap.txt': 'nmap',
            'nbtscan.txt': 'nbtscan',
            '_known-security.txt': 'curl',
            '_rsync_nmap.txt': 'nmap',
            '_imap_nmap.txt': 'nmap',
            '_sip_nmap.txt': 'nmap',
            '_vhosts_': 'ffuf',
            '_nmap.txt': 'nmap',
            '_finger_nmap.txt': 'nmap',
            '_dns_nmap.txt': 'nmap',
            '_feroxbuster_': 'feroxbuster',
            '_gobuster_': 'gobuster',
            '_dirsearch_': 'dirsearch',
            '_ffuf_': 'ffuf',
            '_dirb_': 'dirb',
            '_cassandra_nmap.txt': 'nmap',
            '_curl-robots.txt': 'curl',
            '_nfs_nmap.txt': 'nmap',
            '_multicastdns_nmap.txt': 'nmap',
            '_cups_nmap.txt': 'nmap',
            '_irc_nmap.txt': 'nmap',
            '_distcc_nmap.txt': 'nmap',
            '_ajp_nmap.txt': 'nmap',
            'smbmap-share-permissions.txt': 'smbmap',
            'smbmap-share-permissions.txt': 'smbmap',
            'smbmap-list-contents.txt': 'smbmap',
            'smbmap-list-contents.txt': 'smbmap',
            'smbmap-execute-command.txt': 'smbmap',
            'smbmap-execute-command.txt': 'smbmap',
            '_kerberos_nmap.txt': 'nmap',
            '_kerberos_nmap.txt': 'nmap',
            '_dnsrecon_default.txt': 'dnsrecon',
            '_ssh_nmap.txt': 'nmap',
            '_sslscan.html': 'sslscan',
            '_rpc_architecture.txt': 'getarch',
            '_snmp_onesixtyone.txt': 'onesixtyone',
            '_rmi_nmap.txt': 'nmap'
        }

        for tool in tool_grep.keys():
            if tool in report_file.name:
                return tool_grep[tool]
        return "Unknown"
    def _get_port_dirs(self, protocol):
        if protocol != 'tcp' and protocol != 'udp':
            print(f"Invalid protocol: {protocol}. Supported protocols are 'tcp' and 'udp'.", file=sys.stderr)
            sys.exit(1)
        try: 
            port_dirs = [x for x in Path(self.autorecon_results_dir).iterdir() if x.is_dir() and x.name.startswith(protocol)]
        except Exception as e:
            print(f"Error while getting TCP port directories: {e}", file=sys.stderr)
            sys.exit(1)
        return port_dirs
    def _get_report_files(self, port_dir):
        try:
            report_files = [x for x in Path(port_dir).iterdir() if x.is_file() and x.name.endswith('.txt')]
        except Exception as e:
            print(f"Error while getting report files for port {port_dir.name}: {e}", file=sys.stderr)
            sys.exit(1)
        return report_files
    def _get_service_name(self, port_dir):
        port = port_dir.name.replace('tcp', '').replace('udp', '')
        response = requests.get(f"http://127.0.0.1:9090/ports/{port}")
        if response.status_code == 200:
            response_json = json.loads(response.text)
            if len(response_json['ports']) == 0:
                return "Unknown"
            service_name = response_json['ports'][0][0]
            return self._lookup_preferred_name(service_name)
        else:
            return "Unknown"
    def _lookup_preferred_name(self, service_name):
        service_mappings = {
                'domain': 'DNS',
                'adws': 'ADWS',
                'wsman': 'WINRM',
                'msft-gc': 'LDAP',
                'msft-gc-ssl': 'LDAP',
                'http-rpc-epmap': 'MSRPC',
                'microsoft-ds': 'SMB',
                'epmap': 'MSRPC',
                'kpasswd': 'KERBEROS',
                'ldaps': 'LDAP',
                'ms-sql-s': 'MSSQL',
                'ldap': 'LDAP',
                'netbios-ssn': 'SMB',
                'http': 'HTTP',
                'kerberos': 'KERBEROS',
                'ntp': 'NTP'
            }
        try:
            preferred_name = service_mappings.get(service_name)
            if preferred_name is None:
                return service_name
            return preferred_name
        except Exception as e:
            print(f"Error while looking up preferred name for service {service_name}: {e}", file=sys.stderr)
            return service_name

    def generate_notes(self, gathered_data):

        os.makedirs(f"{self.obsidian_vault_dir}/03 - Content/Write Ups", exist_ok=True)
        os.makedirs(f"{self.obsidian_vault_dir}/03 - Content/Write Ups/{self.challenge_platform}", exist_ok=True)
        os.makedirs(f"{self.obsidian_vault_dir}/03 - Content/Write Ups/{self.challenge_platform}/{self.target_name}", exist_ok=True)
        os.makedirs(f"{self.obsidian_vault_dir}/03 - Content/Write Ups/{self.challenge_platform}/{self.target_name}/0 - Enumeration", exist_ok=True)
        os.makedirs(f"{self.obsidian_vault_dir}/03 - Content/Write Ups/{self.challenge_platform}/{self.target_name}/1 - Exploitation", exist_ok=True)
        os.makedirs(f"{self.obsidian_vault_dir}/03 - Content/Write Ups/{self.challenge_platform}/{self.target_name}/2 - Escalation", exist_ok=True)
        os.makedirs(f"{self.obsidian_vault_dir}/03 - Content/Write Ups/{self.challenge_platform}/{self.target_name}/3 - Loot", exist_ok=True)
        os.makedirs(f"{self.obsidian_vault_dir}/03 - Content/Write Ups/{self.challenge_platform}/{self.target_name}/0 - Enumeration/logs", exist_ok=True)
        os.makedirs(f"{self.obsidian_vault_dir}/03 - Content/Write Ups/{self.challenge_platform}/{self.target_name}/0 - Enumeration/logs/tcp", exist_ok=True)
        os.makedirs(f"{self.obsidian_vault_dir}/03 - Content/Write Ups/{self.challenge_platform}/{self.target_name}/0 - Enumeration/logs/udp", exist_ok=True)

        for port in gathered_data["ports"]["tcp"]:
            current_port = gathered_data["ports"]["tcp"][port]
            tools_used = current_port["tools_used"]
            port_name = current_port["name"].upper()
            tools_used_formatted = "tools: "
            for tool_name in tools_used:
                tools_used_formatted += f"\n  - \"[[{tool_name.upper()}]]\""
            report_dir = current_port["directory"]
            services_formatted = "services: "
            services_formatted += f"\n - \"[[{port}/TCP]]\""
            if port_name != "UNKNOWN":
                services_formatted += f"\n - \"[[{port_name}]]\""
            report_dir = current_port["directory"]
            header_section = f"""---
status: unprocessed
{tools_used_formatted}
{services_formatted}
---
"""
            autorecon_reports = current_port["autorecon_reports"]
            print(len(autorecon_reports))
            ctr = 0
            command_notes = []
            while ctr < len(autorecon_reports):
                report_file_name = autorecon_reports[ctr]['file_name']
                report_file_path = autorecon_reports[ctr]['file_path']
                report_base64_contents = autorecon_reports[ctr]['base64_contents']
                source_tool = autorecon_reports[ctr]['source_tool'].upper()
                command_used_base64 = autorecon_reports[ctr]['base64_command_used']
                if command_used_base64 == "Unknown":
                    ctr += 1
                    continue
                command_used = base64.b64decode(command_used_base64).decode("utf-8")
                report_contents = base64.b64decode(report_base64_contents).decode("utf-8")
                command_notes.append(f"""

## {source_tool} 

~~~ad-info
title: [[{source_tool}]] - Command Results ([[AUTORECON]])

**Command**
```
{command_used}
```

**Output**
```
{report_contents}

```
~~~
""")
                ctr += 1
            formatted_note = ""

            formatted_note += f"""{header_section}


"""
            for command_note in command_notes:
                formatted_note += command_note
            with open(f"{self.obsidian_vault_dir}/03 - Content/Write Ups/{self.challenge_platform}/{self.target_name}/0 - Enumeration/logs/tcp/{port}.md", 'w') as file:
                file.write(formatted_note)

        for port in gathered_data["ports"]["udp"]:
            current_port = gathered_data["ports"]["udp"][port]
            tools_used = current_port["tools_used"]
            port_name = current_port["name"].upper()
            tools_used_formatted = "tools: "
            for tool_name in tools_used:
                tools_used_formatted += f"\n  - \"[[{tool_name.upper()}]]\""
            report_dir = current_port["directory"]
            services_formatted = "services: "
            services_formatted += f"\n - \"[[{port}/UDP]]\""
            if port_name != "UNKNOWN":
                services_formatted += f"\n - \"[[{port_name}]]\""
            report_dir = current_port["directory"]
            header_section = f"""---
status: unprocessed
{tools_used_formatted}
{services_formatted}
---
"""
            autorecon_reports = current_port["autorecon_reports"]
            print(len(autorecon_reports))
            ctr = 0
            command_notes = []
            while ctr < len(autorecon_reports):
                report_file_name = autorecon_reports[ctr]['file_name']
                report_file_path = autorecon_reports[ctr]['file_path']
                report_base64_contents = autorecon_reports[ctr]['base64_contents']
                source_tool = autorecon_reports[ctr]['source_tool'].upper()
                command_used_base64 = autorecon_reports[ctr]['base64_command_used']
                if command_used_base64 == "Unknown":
                    ctr += 1
                    continue
                command_used = base64.b64decode(command_used_base64).decode("utf-8")
                report_contents = base64.b64decode(report_base64_contents).decode("utf-8")
                command_notes.append(f"""

## {source_tool} 

~~~ad-info
title: [[{source_tool}]] - Command Results ([[AUTORECON]])

**Command**
```
{command_used}
```

**Output**
```
{report_contents}

```
~~~
""")
                ctr += 1
            formatted_note = ""

            formatted_note += f"""{header_section}


"""
            for command_note in command_notes:
                formatted_note += command_note
            with open(f"{self.obsidian_vault_dir}/03 - Content/Write Ups/{self.challenge_platform}/{self.target_name}/0 - Enumeration/logs/udp/{port}.md", 'w') as file:
                file.write(formatted_note)

    def make_combined_document(self, gathered_data):
        
        combined_report_header = f"""---
Topics:
  - "[[01 - Pentesting]]"
  - "[[01 - Red Team]]"
Types:
  - "[[02 - Write Ups]]"
tags:
  - writeup
  - {{self.target_name}}
date created: 
date modified:
---
## Objective

___
```ad-info
title:Objective 

- Keep track of the external discovery/enumeration process
```
___

## Discovery

~~~ad-info
title:Machine Information

```txt
10.129.49.30 <hostname>
```

> *Add this info to /etc/hosts* once determined. (Could use netexec or similar tools for this)
~~~

"""

        os.makedirs(f"{self.obsidian_vault_dir}/03 - Content/Write Ups/{self.challenge_platform}/{self.target_name}/0 - Enumeration/ports", exist_ok=True)
        os.makedirs(f"{self.obsidian_vault_dir}/03 - Content/Write Ups/{self.challenge_platform}/{self.target_name}/0 - Enumeration/ports/tcp", exist_ok=True)
        combined_report_progress = f"""

## Progress

|service|port|protocol|Enumerated|Enumeration Note|
|---|---|---|---|---|"""
        combined_report_body = "## Open Ports"
        possible_msrpc_ports = []
        for port in gathered_data["ports"]["tcp"]:
            
            current_port = gathered_data["ports"]["tcp"][port]
            tools_used = current_port["tools_used"]
            port_name = current_port["name"].upper()
            if port_name == "UNKNOWN" and int(port) > 49500 and int(port) < 50000:
                possible_msrpc_ports.append(port)
                continue
            random_id = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(6))
            combined_report_progress += f"""\n|{port_name}|{port}|TCP| <input type=\"checkbox\" unchecked id=\"{random_id}\"> | [[/03 - Content/Write Ups/{self.challenge_platform}/{self.target_name}/0 - Enumeration/ports/tcp/{port}\\|Enumeration Notes]] |"""
            if port_name != "UNKNOWN":
                combined_report_body += f"""

### {port_name} ({port} TCP) %% fold %%

#### Logs

![[03 - Content/Write Ups/{self.challenge_platform}/{self.target_name}/0 - Enumeration/logs/tcp/{port}|{port}]]

#### Notes

![[03 - Content/Write Ups/{self.challenge_platform}/{self.target_name}/0 - Enumeration/ports/tcp/{port}| {port_name} ({port} TCP) - Enumeration Notes]]

#### Tools Used

 - {', '.join(tools_used)}

#### Todos & Reminders

- [ ] blank

"""
        for port in gathered_data["ports"]["udp"]:

            current_port = gathered_data["ports"]["udp"][port]
            tools_used = current_port["tools_used"]
            port_name = current_port["name"].upper()
            if port_name == "UNKNOWN" and port > 49500 and port < 50000:
                possible_msrpc_ports.append(port)
                continue
            random_id = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(6))

            combined_report_progress += f"""\n|{port_name}|{port}|UDP| <input type=\"checkbox\" unchecked id=\"{random_id}\"> | [[/03 - Content/Write Ups/{self.challenge_platform}/{self.target_name}/0 - Enumeration/ports/udp/{port}\\|Enumeration Notes]] |"""             
            combined_report_body += f"""

### {port_name} ({port} UDP) %% fold %%

#### Logs

![[03 - Content/Write Ups/{self.challenge_platform}/{self.target_name}/0 - Enumeration/logs/udp/{port}|{port}]]

#### Notes

![[03 - Content/Write Ups/{self.challenge_platform}/{self.target_name}/0 - Enumeration/ports/udp/{port}| {port_name} ({port} UDP) - Enumeration Notes]]

#### Tools Used

 - {', '.join(tools_used)}

#### Todos & Reminders

- [ ] blank

"""
            
        random_id = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(6))
        progress_footer = f"""

## Unknown Ports (Possible MSRPC Ports) %% fold %%
|Port|Confirmed MSRPC|
|---|---|
"""

        progress_footer += '\n'.join(f"| {port} | <input type=\"checkbox\" unchecked id=\"{random_id}\"> |" for port in possible_msrpc_ports)



        combined_report = combined_report_header + combined_report_progress + combined_report_body + progress_footer
        with open(f"{self.obsidian_vault_dir}/03 - Content/Write Ups/{self.challenge_platform}/{self.target_name}/0 - Enumeration/Enumeration - Master.md", 'w') as file_handle:
            file_handle.write(combined_report)

    def sort_gathered_data(self, gathered_data):
        sorted_data = {
            "ports": {
                "tcp": {},
                "udp": {}
            }
        }
        port_names = []
        for port in gathered_data["ports"]["tcp"].keys():
            port_name = gathered_data["ports"]["tcp"][port]["name"]
            if port_name not in port_names:
                port_names.append(port_name)
        for port_name in port_names:
            for port in gathered_data["ports"]["tcp"].keys():
                if gathered_data["ports"]["tcp"][port]["name"] == port_name:
                    sorted_data["ports"]["tcp"][port] = gathered_data["ports"]["tcp"][port]
        port_names = []
        for port in gathered_data["ports"]["udp"].keys():
            port_name = gathered_data["ports"]["udp"][port]["name"]
            if port_name not in port_names:
                port_names.append(port_name)
        for port_name in port_names:
            for port in gathered_data["ports"]["udp"].keys():
                if gathered_data["ports"]["udp"][port]["name"] == port_name:
                    sorted_data["ports"]["udp"][port] = gathered_data["ports"]["udp"][port]
        return sorted_data
def main():
    autorecon2obidian = AutoRecon2Obsidian()
    print(f"Adding Obsidian-compatible preformatted notes to your vault from autorecon {autorecon2obidian.autorecon_results_dir}")
    gathered_data = autorecon2obidian.gather_autorecon_report_data()
    sorted_data = autorecon2obidian.sort_gathered_data(gathered_data)
    autorecon2obidian.generate_notes(sorted_data)
    autorecon2obidian.make_combined_document(sorted_data)
    sys.exit(0)


if __name__ == "__main__":
    main()